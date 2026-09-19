package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"crcservice/internal/crc"
)

// streamReply 是 /api/v1/stream 响应的测试侧视图。
type streamReply struct {
	Profile    string `json:"profile"`
	Width      uint8  `json:"width"`
	Engine     string `json:"engine"`
	Offset     uint64 `json:"offset"`
	Length     int    `json:"length"`
	NextOffset uint64 `json:"next_offset"`
	Final      bool   `json:"final"`
	State      string `json:"state"`
	Check      string `json:"check"`
}

// postStream 发起一次分块推进并要求成功。
func postStream(t *testing.T, ts *httptest.Server, req map[string]any) streamReply {
	t.Helper()
	status, body := postJSON(t, ts, "/api/v1/stream", req)
	if status != http.StatusOK {
		t.Fatalf("stream chunk failed: status %d body %v", status, body)
	}
	raw, _ := json.Marshal(body)
	var sr streamReply
	if err := json.Unmarshal(raw, &sr); err != nil {
		t.Fatalf("bad stream response: %v", err)
	}
	return sr
}

// splitRest 按给定块长切分 data；块长总和不足时把剩余部分作为最后一块，
// 允许 0 长度块（空分块）。
func splitRest(data []byte, sizes []int) [][]byte {
	chunks := make([][]byte, 0, len(sizes)+1)
	pos := 0
	for _, n := range sizes {
		if n > len(data)-pos {
			n = len(data) - pos
		}
		chunks = append(chunks, data[pos:pos+n])
		pos += n
	}
	if pos < len(data) {
		chunks = append(chunks, data[pos:])
	}
	return chunks
}

// runStream 把 data 按 sizes 切块逐块推进（engines 非空时逐块轮换引擎），
// 校验每块响应的偏移簿记，返回最终校验码。
func runStream(t *testing.T, ts *httptest.Server, base map[string]any, data []byte, sizes []int, engines []string) string {
	t.Helper()
	chunks := splitRest(data, sizes)
	state := ""
	offset := uint64(0)
	var last streamReply
	for i, chunk := range chunks {
		req := map[string]any{}
		for k, v := range base {
			req[k] = v
		}
		req["data"] = base64.StdEncoding.EncodeToString(chunk)
		req["offset"] = offset
		if state != "" {
			req["state"] = state
		}
		if engines != nil {
			req["engine"] = engines[i%len(engines)]
		}
		final := i == len(chunks)-1
		req["final"] = final
		last = postStream(t, ts, req)
		if last.Offset != offset || last.Length != len(chunk) || last.NextOffset != offset+uint64(len(chunk)) {
			t.Fatalf("chunk %d: bad offsets %+v (want off=%d len=%d)", i, last, offset, len(chunk))
		}
		if last.Final != final {
			t.Fatalf("chunk %d: final flag = %v, want %v", i, last.Final, final)
		}
		if !final && last.State == "" {
			t.Fatalf("chunk %d: non-final response missing state", i)
		}
		if final && last.Check == "" {
			t.Fatalf("chunk %d: final response missing check", i)
		}
		state = last.State
		offset += uint64(len(chunk))
	}
	return last.Check
}

// oneShot 直接调单次编码接口取校验码。
func oneShot(t *testing.T, ts *httptest.Server, req map[string]any) string {
	t.Helper()
	status, body := postJSON(t, ts, "/api/v1/checksums", req)
	if status != http.StatusOK {
		t.Fatalf("one-shot failed: %d %v", status, body)
	}
	check, _ := body["check"].(string)
	if check == "" {
		t.Fatalf("one-shot missing check: %v", body)
	}
	return check
}

// 分块合并与整体一致（HTTP 级）：全部内置档，随机载荷按含空块、单字节块、
// 末块长度不同的方式切分，逐块推进的最终校验码必须等于单次接口结果；
// 合并结果再交单次校验接口必须判通过。
func TestHTTPStreamMatchesOneShot(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	rng := rand.New(rand.NewSource(2026))
	data := make([]byte, 1500)
	rng.Read(data)
	enc := base64.StdEncoding.EncodeToString(data)

	chunkings := [][]int{
		{1 << 30}, // 退化：一整块
		{1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		{0, 0, 7, 0, 64, 255, 3, 0, 100, 511},
		{1499, 1},
		{0},
	}
	for _, prof := range crc.ListProfiles() {
		want := oneShot(t, ts, map[string]any{"profile": prof.Name, "data": enc})
		for _, sizes := range chunkings {
			got := runStream(t, ts, map[string]any{"profile": prof.Name}, data, sizes, nil)
			if got != want {
				t.Fatalf("%s sizes=%v: streamed %s != one-shot %s", prof.Name, sizes, got, want)
			}
		}
		// 合并结果交单次校验接口验证，必须判通过。
		check := runStream(t, ts, map[string]any{"profile": prof.Name}, data, []int{100, 200, 300}, nil)
		status, vbody := postJSON(t, ts, "/api/v1/verify", map[string]any{
			"profile": prof.Name, "data": enc, "checksum": check,
		})
		if status != 200 || vbody["valid"] != true {
			t.Fatalf("%s: verify of streamed checksum failed: %d %v", prof.Name, status, vbody)
		}
	}
}

// 空流（只有空的 final 块，或一串空块后接 final 空块）必须等于空载荷单次结果。
func TestHTTPStreamEmptyStream(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	for _, prof := range crc.ListProfiles() {
		want := oneShot(t, ts, map[string]any{"profile": prof.Name, "data": ""})
		got := runStream(t, ts, map[string]any{"profile": prof.Name}, nil, []int{0}, nil)
		if got != want {
			t.Fatalf("%s: empty stream %s != one-shot empty %s", prof.Name, got, want)
		}
		got = runStream(t, ts, map[string]any{"profile": prof.Name}, nil, []int{0, 0, 0}, nil)
		if got != want {
			t.Fatalf("%s: multi-empty stream %s != %s", prof.Name, got, want)
		}
	}
}

// 乱序与重传：无法安放的分块被明确拒绝（409 + STATE_MISMATCH，detail 给出
// 期望偏移）；用上一状态重发当前块是幂等的（得到逐位相同的下一状态）；
// 被拒绝的乱序块不影响后续正确推进。
func TestHTTPStreamOutOfOrderAndDuplicate(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	data := []byte("out-of-order and duplicate chunk handling")
	c0 := base64.StdEncoding.EncodeToString(data[:10])
	c1 := base64.StdEncoding.EncodeToString(data[10:25])
	c2 := base64.StdEncoding.EncodeToString(data[25:])
	want := oneShot(t, ts, map[string]any{"profile": "CRC-32/ISO-HDLC", "data": base64.StdEncoding.EncodeToString(data)})

	// 首块：偏移必须为 0，否则拒绝。
	status, body := postJSON(t, ts, "/api/v1/stream", map[string]any{
		"profile": "CRC-32/ISO-HDLC", "data": c0, "offset": 5,
	})
	if status != http.StatusConflict || errCode(body) != ErrStateMismatch {
		t.Fatalf("first chunk with offset 5: got %d %v", status, body)
	}

	r0 := postStream(t, ts, map[string]any{"profile": "CRC-32/ISO-HDLC", "data": c0, "offset": 0})
	s1 := r0.State

	// 幂等重传：用同一状态重发同一块，得到逐位相同的下一状态。
	r0retry := postStream(t, ts, map[string]any{"profile": "CRC-32/ISO-HDLC", "data": c0, "offset": 0})
	if r0retry.State != s1 {
		t.Fatalf("retry not idempotent: %q vs %q", r0retry.State, s1)
	}

	// 乱序：在期望偏移 10 的状态上提交偏移 25 的块 → 拒绝并给出期望偏移。
	status, body = postJSON(t, ts, "/api/v1/stream", map[string]any{
		"state": s1, "data": c2, "offset": 25,
	})
	if status != http.StatusConflict || errCode(body) != ErrStateMismatch {
		t.Fatalf("out-of-order chunk: got %d %v", status, body)
	}
	detail, _ := body["error"].(map[string]any)["detail"].(string)
	if !strings.Contains(detail, "10") {
		t.Fatalf("mismatch detail should name expected offset 10: %q", detail)
	}

	// 重传已消费块：在 s1 上重发偏移 0 的块 → 拒绝。
	status, body = postJSON(t, ts, "/api/v1/stream", map[string]any{
		"state": s1, "data": c0, "offset": 0,
	})
	if status != http.StatusConflict || errCode(body) != ErrStateMismatch {
		t.Fatalf("duplicate chunk: got %d %v", status, body)
	}

	// 被拒绝的乱序/重复块不污染流：按正确顺序继续，最终结果不变。
	r1 := postStream(t, ts, map[string]any{"state": s1, "data": c1, "offset": 10})
	r2 := postStream(t, ts, map[string]any{"state": r1.State, "data": c2, "offset": 25, "final": true})
	if r2.Check != want {
		t.Fatalf("streamed %s != one-shot %s", r2.Check, want)
	}
}

// 状态令牌完整性：篡改、截断、伪造结构、异密钥签发的令牌一律 STATE_INVALID。
func TestHTTPStreamStateTampering(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	r := postStream(t, ts, map[string]any{"profile": "CRC-16/KERMIT", "data": base64.StdEncoding.EncodeToString([]byte("hello")), "offset": 0})
	good := r.State

	// 未篡改的令牌可用（对照组）。
	postStream(t, ts, map[string]any{"state": good, "data": "", "offset": 5})

	// 翻转令牌载荷区一个字符。
	i := strings.Index(good, ".") + 3
	flip := []byte(good)
	if flip[i] == 'A' {
		flip[i] = 'B'
	} else {
		flip[i] = 'A'
	}
	// 篡改 MAC 区一个字符。
	j := len(good) - 2
	flipMAC := []byte(good)
	if flipMAC[j] == 'A' {
		flipMAC[j] = 'B'
	} else {
		flipMAC[j] = 'A'
	}

	badTokens := []string{
		string(flip),       // 载荷被改 → MAC 不匹配
		string(flipMAC),    // MAC 被改
		good[:len(good)-4], // 截断
		"v1.",              // 缺段
		"v2." + good[3:],   // 版本不符
		"v1.@@@.@@@",       // 非法 base64
		"not-a-token",      // 完全非法
		good + "extra",     // 尾部垃圾
	}
	for k, tok := range badTokens {
		status, body := postJSON(t, ts, "/api/v1/stream", map[string]any{
			"state": tok, "data": "", "offset": 5,
		})
		if status != http.StatusBadRequest || errCode(body) != ErrStateInvalid {
			t.Fatalf("bad token %d (%q): got %d %v, want 400 %s", k, tok, status, body, ErrStateInvalid)
		}
	}

	// 异密钥服务签发的令牌在本服务必须被拒。
	otherTS := httptest.NewServer(newServerWithKey([]byte("a different key")).Handler())
	defer otherTS.Close()
	ro := postStream(t, otherTS, map[string]any{
		"profile": "CRC-16/KERMIT", "data": base64.StdEncoding.EncodeToString([]byte("hello")), "offset": 0,
	})
	status, body := postJSON(t, ts, "/api/v1/stream", map[string]any{
		"state": ro.State, "data": "", "offset": 5,
	})
	if status != http.StatusBadRequest || errCode(body) != ErrStateInvalid {
		t.Fatalf("foreign-key token accepted: %d %v", status, body)
	}
}

// 参数档绑定：续传时给出与令牌内不同的档必须拒绝；省略档名则沿用令牌内
// 已认证参数档正常推进。
func TestHTTPStreamParamsBoundToState(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	data := []byte("params are bound to the stream state")
	first := base64.StdEncoding.EncodeToString(data[:8])
	rest := base64.StdEncoding.EncodeToString(data[8:])

	r := postStream(t, ts, map[string]any{"profile": "CRC-8", "data": first, "offset": 0})

	// 换档续传 → 409 STATE_MISMATCH。
	status, body := postJSON(t, ts, "/api/v1/stream", map[string]any{
		"state": r.State, "profile": "CRC-16/MODBUS", "data": rest, "offset": 8, "final": true,
	})
	if status != http.StatusConflict || errCode(body) != ErrStateMismatch {
		t.Fatalf("profile switch: got %d %v", status, body)
	}

	// 等价显式参数续传（与 CRC-8 同参数）→ 允许。
	eq := postStream(t, ts, map[string]any{
		"state":  r.State,
		"params": map[string]any{"width": 8, "poly": "0x07", "init": 0, "ref_in": false, "ref_out": false, "xor_out": 0},
		"data":   rest, "offset": 8, "final": true,
	})
	want := oneShot(t, ts, map[string]any{"profile": "CRC-8", "data": base64.StdEncoding.EncodeToString(data)})
	if eq.Check != want {
		t.Fatalf("explicit-equivalent continuation %s != %s", eq.Check, want)
	}

	// 省略档名续传 → 沿用令牌内参数档，结果一致。
	r2 := postStream(t, ts, map[string]any{"profile": "CRC-8", "data": first, "offset": 0})
	fin := postStream(t, ts, map[string]any{"state": r2.State, "data": rest, "offset": 8, "final": true})
	if fin.Check != want || fin.Profile != "CRC-8" {
		t.Fatalf("profile-less continuation: %+v want check %s", fin, want)
	}
}

// 随机临时档（含非字节宽度、ref_in!=ref_out、xor_out 非零）经 HTTP 分块：
// 逐块混用引擎，合并结果必须等于同参数单次接口结果，且能被单次校验接口接受。
func TestHTTPStreamRandomAdHocProfiles(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	rng := rand.New(rand.NewSource(777))
	for iter := 0; iter < 60; iter++ {
		w := 8 + rng.Intn(57)
		mask := crc.Mask(uint8(w))
		params := map[string]any{
			"width":   w,
			"poly":    fmt.Sprintf("0x%x", (rng.Uint64()|1)&mask),
			"init":    fmt.Sprintf("0x%x", rng.Uint64()&mask),
			"ref_in":  rng.Intn(2) == 0,
			"ref_out": rng.Intn(2) == 0,
			"xor_out": fmt.Sprintf("0x%x", rng.Uint64()&mask),
		}
		data := make([]byte, rng.Intn(400))
		rng.Read(data)
		enc := base64.StdEncoding.EncodeToString(data)

		want := oneShot(t, ts, map[string]any{"params": params, "data": enc})

		// 随机切分（含空块），逐块随机引擎。
		var sizes []int
		for rem := len(data); rem > 0; {
			n := rng.Intn(23)
			sizes = append(sizes, n)
			if n == 0 {
				rem-- // 空块不消费数据，但仍保证循环终止
			} else {
				rem -= n
			}
		}
		if len(sizes) == 0 {
			sizes = []int{0}
		}
		engines := []string{"table", "bitwise"}
		got := runStream(t, ts, map[string]any{"params": params}, data, sizes,
			[]string{engines[rng.Intn(2)], engines[rng.Intn(2)]})
		if got != want {
			t.Fatalf("iter %d params=%v: streamed %s != one-shot %s", iter, params, got, want)
		}

		// 合并结果交单次校验接口必须判通过。
		status, vbody := postJSON(t, ts, "/api/v1/verify", map[string]any{
			"params": params, "data": enc, "checksum": got,
		})
		if status != 200 || vbody["valid"] != true {
			t.Fatalf("iter %d: verify of streamed checksum failed: %d %v", iter, status, vbody)
		}
	}
}

// 篡改检测：合并前任意一块被翻转一个比特，最终校验码必须改变，
// 且原数据配该码在单次校验接口判失败。
func TestHTTPStreamChunkBitFlipDetected(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	rng := rand.New(rand.NewSource(5150))
	data := make([]byte, 300)
	rng.Read(data)
	enc := base64.StdEncoding.EncodeToString(data)
	sizes := []int{50, 100, 0, 150}

	for _, prof := range crc.ListProfiles() {
		base := map[string]any{"profile": prof.Name}
		good := runStream(t, ts, base, data, sizes, nil)

		// 在第二块（偏移 50）与最后一块各翻一个比特。
		for _, at := range []int{50, 299} {
			corrupt := append([]byte(nil), data...)
			corrupt[at] ^= 0x10
			bad := runStream(t, ts, base, corrupt, sizes, nil)
			if bad == good {
				t.Fatalf("%s: flipping byte %d left streamed checksum %s unchanged", prof.Name, at, bad)
			}
			// 原数据 + 篡改链算出的码 → 单次校验判失败。
			_, vbody := postJSON(t, ts, "/api/v1/verify", map[string]any{
				"profile": prof.Name, "data": enc, "checksum": bad,
			})
			if vbody["valid"] != false {
				t.Fatalf("%s: tampered-chain checksum verified against original data", prof.Name)
			}
		}
	}
}

// 流式接口的输入校验：未知档名、非法 base64、非法引擎、方法错误，
// 全部在计算前以结构化错误拒绝。
func TestHTTPStreamErrors(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	enc := base64.StdEncoding.EncodeToString([]byte("x"))

	status, body := postJSON(t, ts, "/api/v1/stream", map[string]any{"profile": "NOPE", "data": enc})
	if status != http.StatusNotFound || errCode(body) != ErrUnknownProfile {
		t.Fatalf("unknown profile: %d %v", status, body)
	}
	status, body = postJSON(t, ts, "/api/v1/stream", map[string]any{"profile": "CRC-8", "data": "@@@"})
	if status != http.StatusBadRequest || errCode(body) != ErrDataFormat {
		t.Fatalf("bad base64: %d %v", status, body)
	}
	status, body = postJSON(t, ts, "/api/v1/stream", map[string]any{"profile": "CRC-8", "data": enc, "engine": "warp"})
	if errCode(body) != ErrInvalidEngine {
		t.Fatalf("bad engine: %d %v", status, body)
	}
	status, body = postJSON(t, ts, "/api/v1/stream", map[string]any{"data": enc})
	if errCode(body) != ErrMissingProfile {
		t.Fatalf("missing profile: %d %v", status, body)
	}
	status, body = postJSON(t, ts, "/api/v1/stream", map[string]any{
		"params": map[string]any{"width": 4, "poly": 3, "init": 0, "ref_in": false, "ref_out": false, "xor_out": 0},
		"data":   enc,
	})
	if errCode(body) != ErrInvalidParameter {
		t.Fatalf("bad params: %d %v", status, body)
	}
	resp, err := http.Get(ts.URL + "/api/v1/stream")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/v1/stream = %d", resp.StatusCode)
	}
}

// 并发流式核算：多条独立的流并发推进，互不串扰，各自合并结果都等于
// 本地参考值。
func TestHTTPStreamConcurrent(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	profs := crc.ListProfiles()
	rng := rand.New(rand.NewSource(88))

	type job struct {
		prof  crc.Profile
		data  []byte
		sizes []int
		want  string
	}
	jobs := make([]job, 24)
	for i := range jobs {
		p := profs[rng.Intn(len(profs))]
		d := make([]byte, 1+rng.Intn(500))
		rng.Read(d)
		var sizes []int
		for rem := len(d); rem > 0; {
			n := rng.Intn(41)
			sizes = append(sizes, n)
			if n == 0 {
				rem--
			} else {
				rem -= n
			}
		}
		jobs[i] = job{
			prof:  p,
			data:  d,
			sizes: sizes,
			want:  crc.FormatHex(crc.Compute(p.Params, d, crc.EngineTable), p.Params.Width),
		}
	}

	var wg sync.WaitGroup
	errs := make(chan string, len(jobs))
	for i := range jobs {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			// 每块轮换引擎，交叉验证并发下双引擎同余。
			got := streamOrErr(ts, map[string]any{"profile": j.prof.Name}, j.data, j.sizes,
				[]string{"bitwise", "table"})
			if got != j.want {
				errs <- fmt.Sprintf("%s: got %s want %s", j.prof.Name, got, j.want)
			}
		}(jobs[i])
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}

// streamOrErr 是 runStream 的「不 t.Fatal」版本，供并发 goroutine 使用：
// 任何协议级失败都返回空串，由调用方与期望值比较后统一报错。
func streamOrErr(ts *httptest.Server, base map[string]any, data []byte, sizes []int, engines []string) string {
	chunks := splitRest(data, sizes)
	state := ""
	offset := uint64(0)
	check := ""
	for i, chunk := range chunks {
		req := map[string]any{}
		for k, v := range base {
			req[k] = v
		}
		req["data"] = base64.StdEncoding.EncodeToString(chunk)
		req["offset"] = offset
		if state != "" {
			req["state"] = state
		}
		if engines != nil {
			req["engine"] = engines[i%len(engines)]
		}
		req["final"] = i == len(chunks)-1
		resp, err := http.Post(ts.URL+"/api/v1/stream", "application/json",
			strings.NewReader(mustJSON(req)))
		if err != nil {
			return ""
		}
		var sr streamReply
		err = json.NewDecoder(resp.Body).Decode(&sr)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || err != nil {
			return ""
		}
		state = sr.State
		check = sr.Check
		offset += uint64(len(chunk))
	}
	return check
}

func mustJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(raw)
}
