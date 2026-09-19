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

// postChunk 提交一个分块；state 为空串表示首块。返回 HTTP 状态与响应体。
func postChunk(t *testing.T, ts *httptest.Server, base map[string]any, offset int, state string, data []byte, final bool) (int, map[string]any) {
	t.Helper()
	req := map[string]any{}
	for k, v := range base {
		req[k] = v
	}
	req["offset"] = offset
	req["data"] = base64.StdEncoding.EncodeToString(data)
	if state != "" {
		req["state"] = state
	}
	if final {
		req["final"] = true
	}
	return postJSON(t, ts, "/api/v1/chunks", req)
}

// streamInOrder 按顺序逐块推进（每块可指定引擎），返回最终校验码与末态令牌。
func streamInOrder(t *testing.T, ts *httptest.Server, base map[string]any, chunks [][]byte, engines []string) (string, string) {
	t.Helper()
	state := ""
	offset := 0
	var body map[string]any
	for i, c := range chunks {
		b := map[string]any{}
		for k, v := range base {
			b[k] = v
		}
		if engines != nil && engines[i] != "" {
			b["engine"] = engines[i]
		}
		status, resp := postChunk(t, ts, b, offset, state, c, i == len(chunks)-1)
		if status != http.StatusOK {
			t.Fatalf("chunk %d: status %d body %v", i, status, resp)
		}
		if int(resp["offset"].(float64)) != offset || int(resp["bytes"].(float64)) != len(c) {
			t.Fatalf("chunk %d: bad echo %v", i, resp)
		}
		if int(resp["next_offset"].(float64)) != offset+len(c) {
			t.Fatalf("chunk %d: bad next_offset %v", i, resp)
		}
		state, _ = resp["state"].(string)
		if state == "" {
			t.Fatalf("chunk %d: empty state token", i)
		}
		offset += len(c)
		body = resp
	}
	check, _ := body["check"].(string)
	return check, state
}

func oneShotCheck(t *testing.T, ts *httptest.Server, base map[string]any, data []byte) string {
	t.Helper()
	req := map[string]any{}
	for k, v := range base {
		req[k] = v
	}
	req["data"] = base64.StdEncoding.EncodeToString(data)
	status, body := postJSON(t, ts, "/api/v1/checksums", req)
	if status != http.StatusOK {
		t.Fatalf("one-shot: status %d body %v", status, body)
	}
	return body["check"].(string)
}

// 分块流式合并与一次性计算逐位一致：全部内置档、公开向量与较长载荷、
// 多种切分（含空块、单字节块、不等长末块、退化单块）；合并结果经单次
// 校验接口判通过。
func TestHTTPChunkedMatchesOneShot(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	rng := rand.New(rand.NewSource(4242))
	long := make([]byte, 1024)
	rng.Read(long)

	cases := []struct {
		name   string
		data   []byte
		splits [][]byte
	}{
		{"vector-degenerate", crc.StandardVector, [][]byte{crc.StandardVector}},
		{"vector-bytes", crc.StandardVector, splitEvery(crc.StandardVector, 1)},
		{"vector-uneven", crc.StandardVector, [][]byte{
			crc.StandardVector[:2], {}, crc.StandardVector[2:7], crc.StandardVector[7:],
		}},
		{"long-3", long, [][]byte{long[:300], long[300:700], long[700:]}},
		{"long-empty-chunks", long, [][]byte{{}, long[:1], {}, long[1:1023], {}, long[1023:], {}}},
		{"empty-stream", nil, nil},
	}
	for _, prof := range crc.ListProfiles() {
		base := map[string]any{"profile": prof.Name}
		for _, tc := range cases {
			want := oneShotCheck(t, ts, base, tc.data)
			var got string
			if len(tc.splits) == 0 {
				// 空流：一个分块都不提交，直接 final。
				status, body := postChunk(t, ts, base, 0, "", nil, true)
				if status != http.StatusOK {
					t.Fatalf("%s/%s: %d %v", prof.Name, tc.name, status, body)
				}
				got, _ = body["check"].(string)
			} else {
				got, _ = streamInOrder(t, ts, base, tc.splits, nil)
			}
			if got != want {
				t.Fatalf("%s/%s: chunked %s != one-shot %s", prof.Name, tc.name, got, want)
			}
			// 对合并结果做单次校验接口验证，必须判通过。
			_, vbody := postJSON(t, ts, "/api/v1/verify", map[string]any{
				"profile":  prof.Name,
				"data":     base64.StdEncoding.EncodeToString(tc.data),
				"checksum": got,
			})
			if vbody["valid"] != true {
				t.Fatalf("%s/%s: merged check %s rejected by verify: %v", prof.Name, tc.name, got, vbody)
			}
		}
		// 公开向量：分块合并必须等于 catalog 公布值。
		got, _ := streamInOrder(t, ts, base, [][]byte{crc.StandardVector[:4], crc.StandardVector[4:]}, nil)
		if got != fmt.Sprintf("%0*x", crc.HexDigits(prof.Params.Width), prof.Check) {
			t.Fatalf("%s: chunked vector %s != catalog", prof.Name, got)
		}
	}
}

func splitEvery(data []byte, n int) [][]byte {
	var out [][]byte
	for i := 0; i < len(data); i += n {
		out = append(out, data[i:i+n])
	}
	return out
}

// 随机构造的合法临时档（含混合反转、非字节宽度、xor_out 非零）经 HTTP
// 分块推进，合并结果必须与同参数单次接口逐位一致。
func TestHTTPChunkedRandomAdHocParams(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	rng := rand.New(rand.NewSource(20260919))
	for iter := 0; iter < 40; iter++ {
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
		base := map[string]any{"params": params}
		data := make([]byte, rng.Intn(300))
		rng.Read(data)
		chunks := [][]byte{data[:len(data)/3], data[len(data)/3 : 2*len(data)/3], data[2*len(data)/3:]}
		want := oneShotCheck(t, ts, base, data)
		got, _ := streamInOrder(t, ts, base, chunks, nil)
		if got != want {
			t.Fatalf("iter %d params %v: chunked %s != one-shot %s", iter, params, got, want)
		}
	}
}

// 乱序与错位重传：服务依据分块携带的偏移与令牌内的流位置，拒绝无法安放的
// 分块并给出明确错误码；正确顺序重传则幂等，最终结果不受影响。
func TestHTTPChunkOutOfOrderAndRetransmit(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	base := map[string]any{"profile": "CRC-32/ISO-HDLC"}
	c0 := []byte("first-chunk/")
	c1 := []byte("second-chunk/")
	c2 := []byte("third-chunk-final")
	full := append(append(append([]byte(nil), c0...), c1...), c2...)
	want := oneShotCheck(t, ts, base, full)

	// 首块：offset 0，无 state。
	status, r0 := postChunk(t, ts, base, 0, "", c0, false)
	if status != http.StatusOK {
		t.Fatalf("chunk0: %d %v", status, r0)
	}
	s1, _ := r0["state"].(string)

	// 乱序：拿着偏移 0 之后的令牌，试图安放偏移更靠后的块 → 拒绝。
	status, body := postChunk(t, ts, base, len(c0)+len(c1), s1, c2, false)
	if status != http.StatusUnprocessableEntity || errCode(body) != ErrStateOffset {
		t.Fatalf("out-of-order chunk accepted: %d %v", status, body)
	}
	// 错位：偏移与令牌内流位置不符 → 拒绝。
	status, body = postChunk(t, ts, base, 0, s1, c1, false)
	if errCode(body) != ErrStateOffset {
		t.Fatalf("misplaced chunk accepted: %d %v", status, body)
	}
	// 无令牌的首块偏移非 0 → 拒绝。
	status, body = postChunk(t, ts, base, 5, "", c1, false)
	if errCode(body) != ErrStateOffset {
		t.Fatalf("non-zero first offset accepted: %d %v", status, body)
	}

	// 重传首块（相同输入）→ 幂等，返回完全相同的令牌。
	status, r0b := postChunk(t, ts, base, 0, "", c0, false)
	if status != http.StatusOK || r0b["state"] != s1 {
		t.Fatalf("retransmit not idempotent: %d %v vs %v", status, r0b, r0)
	}

	// 正常推进第二块。
	status, r1 := postChunk(t, ts, base, len(c0), s1, c1, false)
	if status != http.StatusOK {
		t.Fatalf("chunk1: %d %v", status, r1)
	}
	s2, _ := r1["state"].(string)

	// 重传第二块（携带其对应的旧令牌）→ 幂等，结果不变。
	status, r1b := postChunk(t, ts, base, len(c0), s1, c1, false)
	if status != http.StatusOK || r1b["state"] != s2 {
		t.Fatalf("retransmit of chunk1 not idempotent: %d %v", status, r1b)
	}
	// 用过期令牌重复首块（流已前进）→ 拒绝。
	status, body = postChunk(t, ts, base, 0, s2, c0, false)
	if errCode(body) != ErrStateOffset {
		t.Fatalf("stale duplicate accepted: %d %v", status, body)
	}

	// 末块收尾：合并结果与一次性计算逐位一致。
	status, r2 := postChunk(t, ts, base, len(c0)+len(c1), s2, c2, true)
	if status != http.StatusOK {
		t.Fatalf("chunk2: %d %v", status, r2)
	}
	if r2["check"] != want {
		t.Fatalf("merged %v != one-shot %v", r2["check"], want)
	}
}

// 中间状态令牌的完整性：篡改、跨参数档混用、跨密钥实例使用，一律在计算前拒绝。
func TestHTTPChunkStateIntegrity(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	base := map[string]any{"profile": "CRC-16/CCITT-FALSE"}
	_, r0 := postChunk(t, ts, base, 0, "", []byte("hello "), false)
	state, _ := r0["state"].(string)

	// 篡改令牌一个字符 → STATE_FORMAT_ERROR。
	tampered := []byte(state)
	if tampered[5] == 'A' {
		tampered[5] = 'B'
	} else {
		tampered[5] = 'A'
	}
	status, body := postChunk(t, ts, base, 6, string(tampered), []byte("world"), true)
	if status != http.StatusBadRequest || errCode(body) != ErrStateFormat {
		t.Fatalf("tampered token accepted: %d %v", status, body)
	}
	// 明显非法令牌。
	status, body = postChunk(t, ts, base, 6, "not-a-token", []byte("world"), true)
	if errCode(body) != ErrStateFormat {
		t.Fatalf("garbage token accepted: %d %v", status, body)
	}
	// 甲档的令牌拿去乙档续算 → STATE_PARAMS_MISMATCH。
	status, body = postChunk(t, ts, map[string]any{"profile": "CRC-8"}, 6, state, []byte("world"), true)
	if status != http.StatusUnprocessableEntity || errCode(body) != ErrStateParams {
		t.Fatalf("cross-profile token accepted: %d %v", status, body)
	}
	// 等价的显式临时档与具名档指纹相同，令牌可以续算（语义一致的档）。
	status, body = postChunk(t, ts, map[string]any{"params": map[string]any{
		"width": 16, "poly": "0x1021", "init": "0xffff",
		"ref_in": false, "ref_out": false, "xor_out": "0x0",
	}}, 6, state, []byte("world"), true)
	if status != http.StatusOK {
		t.Fatalf("equivalent ad-hoc params rejected: %d %v", status, body)
	}
	if body["check"] != oneShotCheck(t, ts, base, []byte("hello world")) {
		t.Fatalf("cross-representation continuation mismatch: %v", body)
	}

	// 另一密钥的实例拒绝本实例令牌。
	other := NewServer()
	other.stateKey = []byte("another deployment key")
	ts2 := httptest.NewServer(other.Handler())
	defer ts2.Close()
	status, body = postChunk(t, ts2, base, 6, state, []byte("world"), true)
	if status != http.StatusBadRequest || errCode(body) != ErrStateFormat {
		t.Fatalf("foreign-key token accepted: %d %v", status, body)
	}
}

// 同一段流的不同分块可以混用双引擎（两路严格同余），合并结果不变。
func TestHTTPChunkCrossEngine(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	data := []byte("cross-engine chunked stream payload, long enough to matter")
	chunks := [][]byte{data[:13], data[13:40], data[40:]}
	for _, prof := range crc.ListProfiles() {
		base := map[string]any{"profile": prof.Name}
		want := oneShotCheck(t, ts, base, data)
		got, _ := streamInOrder(t, ts, base, chunks, []string{"table", "bitwise", "table"})
		if got != want {
			t.Fatalf("%s: cross-engine chunked %s != one-shot %s", prof.Name, got, want)
		}
		got2, _ := streamInOrder(t, ts, base, chunks, []string{"bitwise", "bitwise", "bitwise"})
		if got2 != want {
			t.Fatalf("%s: all-bitwise chunked %s != one-shot %s", prof.Name, got2, want)
		}
	}
}

// 翻转合并前任意一块的一个比特：最终校验码必须改变，且对原数据校验判失败。
func TestHTTPChunkBitFlipDetected(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	data := []byte("flip one bit in any single chunk before merging")
	chunks := [][]byte{data[:11], data[11:30], data[30:]}
	for _, prof := range crc.ListProfiles() {
		base := map[string]any{"profile": prof.Name}
		good, _ := streamInOrder(t, ts, base, chunks, nil)
		// 翻转中间块的一个比特。
		bad1 := append([]byte(nil), chunks[1]...)
		bad1[3] ^= 0x10
		bad, _ := streamInOrder(t, ts, base, [][]byte{chunks[0], bad1, chunks[2]}, nil)
		if bad == good {
			t.Fatalf("%s: bit flip in chunk did not change merged check", prof.Name)
		}
		_, vbody := postJSON(t, ts, "/api/v1/verify", map[string]any{
			"profile":  prof.Name,
			"data":     base64.StdEncoding.EncodeToString(data),
			"checksum": bad,
		})
		if vbody["valid"] != false {
			t.Fatalf("%s: tampered merged check accepted for original data: %v", prof.Name, vbody)
		}
	}
}

// 分块接口的前置校验：未知档名、参数越界、格式错误、方法错误等都在计算前拒绝。
func TestHTTPChunkErrors(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	// 方法错误。
	resp, err := http.Get(ts.URL + "/api/v1/chunks")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/v1/chunks = %d", resp.StatusCode)
	}

	cases := []struct {
		name string
		body map[string]any
		code string
	}{
		{"unknown profile", map[string]any{"profile": "NOPE", "offset": 0, "data": ""}, ErrUnknownProfile},
		{"missing profile", map[string]any{"offset": 0, "data": ""}, ErrMissingProfile},
		{"profile and params", map[string]any{
			"profile": "CRC-8", "offset": 0, "data": "",
			"params": map[string]any{"width": 8, "poly": 7, "init": 0, "ref_in": false, "ref_out": false, "xor_out": 0},
		}, ErrProfileAndParams},
		{"invalid params", map[string]any{
			"params": map[string]any{"width": 3, "poly": 1, "init": 0, "ref_in": false, "ref_out": false, "xor_out": 0},
			"offset": 0, "data": "",
		}, ErrInvalidParameter},
		{"missing offset", map[string]any{"profile": "CRC-8", "data": ""}, ErrInvalidParameter},
		{"bad base64", map[string]any{"profile": "CRC-8", "offset": 0, "data": "@@@"}, ErrDataFormat},
		{"bad engine", map[string]any{"profile": "CRC-8", "offset": 0, "data": "", "engine": "warp"}, ErrInvalidEngine},
	}
	for _, tc := range cases {
		_, body := postJSON(t, ts, "/api/v1/chunks", tc.body)
		if errCode(body) != tc.code {
			t.Fatalf("%s: got %v, want code %s", tc.name, body, tc.code)
		}
	}

	// 未知字段 / 非法 JSON。
	resp, err = http.Post(ts.URL+"/api/v1/chunks", "application/json",
		strings.NewReader(`{"profile":"CRC-8","offset":0,"data":"","bogus":1}`))
	if err != nil {
		t.Fatal(err)
	}
	var eb ErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&eb); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if eb.Error.Code != ErrInvalidJSON {
		t.Fatalf("unknown field not rejected: %+v", eb)
	}
}

// 并发下多条独立流式会话与批量请求混跑：服务无状态，结果必须确定且互不串扰。
func TestHTTPChunkedAndBatchConcurrent(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	profs := crc.ListProfiles()
	var wg sync.WaitGroup
	errCh := make(chan string, 64)
	for w := 0; w < 12; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for k := 0; k < 20; k++ {
				prof := profs[(worker+k)%len(profs)]
				data := []byte(fmt.Sprintf("worker-%d-stream-%d-with-some-length", worker, k))
				chunks := [][]byte{data[:7], data[7:25], data[25:]}
				base := map[string]any{"profile": prof.Name}
				want := oneShotCheck(t, ts, base, data)
				eng := []string{"table", "bitwise"}[(worker+k)%2]
				got, _ := streamInOrder(t, ts, base, chunks, []string{eng, eng, eng})
				if got != want {
					errCh <- fmt.Sprintf("worker %d iter %d: %s != %s", worker, k, got, want)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errCh)
	for e := range errCh {
		t.Fatal(e)
	}
}
