package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"crcservice/internal/crc"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(NewServer().Handler())
}

func postJSON(t *testing.T, ts *httptest.Server, path string, body any) (int, map[string]any) {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(raw)
	} else {
		rdr = bytes.NewReader(nil)
	}
	resp, err := http.Post(ts.URL+path, "application/json", rdr)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("response not json: %v", err)
	}
	return resp.StatusCode, out
}

func errCode(m map[string]any) string {
	e, ok := m["error"].(map[string]any)
	if !ok {
		return ""
	}
	c, _ := e["code"].(string)
	return c
}

// 预置公开向量算例可直接通过 HTTP 核对。
func TestHealthAndProfilesAndVectors(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", resp.StatusCode)
	}
	var health HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if health.Status != "ok" || health.Version == "" || health.Profiles == 0 {
		t.Fatalf("bad health body: %+v", health)
	}

	resp2, err := http.Get(ts.URL + "/api/v1/profiles")
	if err != nil {
		t.Fatal(err)
	}
	var pv struct {
		Profiles []struct {
			Name   string     `json:"name"`
			Params crc.Params `json:"params"`
			Check  string     `json:"check_123456789"`
		} `json:"profiles"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&pv); err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if len(pv.Profiles) != health.Profiles {
		t.Fatalf("profile count mismatch: %d vs %d", len(pv.Profiles), health.Profiles)
	}
	byName := map[string]string{}
	for _, p := range pv.Profiles {
		byName[p.Name] = p.Check
		if p.Params.Width == 0 {
			t.Fatalf("profile %s exposes no params", p.Name)
		}
	}
	if byName["CRC-8"] != "f4" || byName["CRC-16/CCITT-FALSE"] != "29b1" {
		t.Fatalf("standard checks wrong: %v", byName)
	}

	resp3, err := http.Get(ts.URL + "/api/v1/vectors")
	if err != nil {
		t.Fatal(err)
	}
	var vv struct {
		Vectors []Vector `json:"vectors"`
	}
	if err := json.NewDecoder(resp3.Body).Decode(&vv); err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if len(vv.Vectors) == 0 || vv.Vectors[0].InputBase64 != base64.StdEncoding.EncodeToString([]byte("123456789")) {
		t.Fatalf("bad vectors: %+v", vv.Vectors)
	}
}

// 公开向量：通过编码接口对「123456789」算出的码必须等于公布值，
// 且 bitwise/table 两路一致。
func TestHTTPPublicVectorAndEngines(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	payload := map[string]any{
		"profile": "CRC-16/CCITT-FALSE",
		"data":    base64.StdEncoding.EncodeToString([]byte("123456789")),
	}
	for _, eng := range []string{"", "table", "bitwise"} {
		if eng != "" {
			payload["engine"] = eng
		} else {
			delete(payload, "engine")
		}
		status, body := postJSON(t, ts, "/api/v1/checksums", payload)
		if status != http.StatusOK {
			t.Fatalf("engine %q status %d body %v", eng, status, body)
		}
		if body["check"] != "29b1" {
			t.Fatalf("engine %q check = %v, want 29b1", eng, body["check"])
		}
		if uint8(body["width"].(float64)) != 16 {
			t.Fatalf("width = %v", body["width"])
		}
	}
}

// 编码 → 校验 自洽：任意载荷经编码接口拿到的码交给校验接口必须通过；
// 同时覆盖空载荷与非 ASCII 字节。
func TestHTTPRoundTrip(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	raws := [][]byte{nil, {}, []byte(""), []byte("a"), []byte{0x00, 0xff, 0x88}, []byte("中文 payload")}
	for _, prof := range crc.ListProfiles() {
		for _, raw := range raws {
			enc := base64.StdEncoding.EncodeToString(raw)
			status, body := postJSON(t, ts, "/api/v1/checksums", map[string]any{
				"profile": prof.Name, "data": enc,
			})
			if status != 200 {
				t.Fatalf("compute %s failed: %d %v", prof.Name, status, body)
			}
			check, _ := body["check"].(string)
			status2, vbody := postJSON(t, ts, "/api/v1/verify", map[string]any{
				"profile": prof.Name, "data": enc, "checksum": check,
			})
			if status2 != 200 || vbody["valid"] != true || vbody["residual"] != fmt.Sprintf("%0*x", crc.HexDigits(prof.Params.Width), 0) {
				t.Fatalf("%s data=%x verify: %d %v", prof.Name, raw, status2, vbody)
			}
		}
	}
}

// 单比特翻转经 HTTP 必须判失败，且翻转校验码同样失败。
func TestHTTPSingleBitFlipFails(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	raw := []byte("tamper detection over HTTP")
	enc := base64.StdEncoding.EncodeToString(raw)
	for _, prof := range crc.ListProfiles() {
		_, body := postJSON(t, ts, "/api/v1/checksums", map[string]any{
			"profile": prof.Name, "data": enc,
		})
		check, _ := body["check"].(string)
		checkVal, err := crc.ParseHex(check, prof.Params.Width)
		if err != nil {
			t.Fatal(err)
		}

		// 翻转数据中间一个字节的一个比特。
		corrupt := append([]byte(nil), raw...)
		corrupt[len(corrupt)/2] ^= 0x01
		_, vbody := postJSON(t, ts, "/api/v1/verify", map[string]any{
			"profile":  prof.Name,
			"data":     base64.StdEncoding.EncodeToString(corrupt),
			"checksum": check,
		})
		if vbody["valid"] != false {
			t.Fatalf("%s: corrupted data accepted: %v", prof.Name, vbody)
		}

		// 翻转校验码的一个比特。
		bad := crc.FormatHex(checkVal^1, prof.Params.Width)
		_, vbody2 := postJSON(t, ts, "/api/v1/verify", map[string]any{
			"profile":  prof.Name,
			"data":     enc,
			"checksum": bad,
		})
		if vbody2["valid"] != false {
			t.Fatalf("%s: corrupted checksum accepted: %v", prof.Name, vbody2)
		}
	}
}

// 显式临时参数档：与同名具名档给出完全一致的结果；
// 非法显式参数在计算前被拒绝。
func TestHTTPExplicitParams(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	enc := base64.StdEncoding.EncodeToString([]byte("123456789"))
	explicit := map[string]any{
		"params": map[string]any{
			"width": 16, "poly": "0x1021", "init": "0xffff",
			"ref_in": false, "ref_out": false, "xor_out": "0x0",
		},
		"data": enc,
	}
	status, body := postJSON(t, ts, "/api/v1/checksums", explicit)
	if status != 200 || body["check"] != "29b1" {
		t.Fatalf("explicit params: %d %v", status, body)
	}

	bad := []map[string]any{
		// 位宽越界
		{"params": map[string]any{"width": 4, "poly": 3, "init": 0, "ref_in": false, "ref_out": false, "xor_out": 0}, "data": enc},
		// 多项式超界
		{"params": map[string]any{"width": 8, "poly": 0x100, "init": 0, "ref_in": false, "ref_out": false, "xor_out": 0}, "data": enc},
		// 偶数多项式（缺常数项）
		{"params": map[string]any{"width": 8, "poly": 0x30, "init": 0, "ref_in": false, "ref_out": false, "xor_out": 0}, "data": enc},
		// 缺少必填字段
		{"params": map[string]any{"width": 8, "poly": 7, "init": 0}, "data": enc},
	}
	for i, b := range bad {
		status, body = postJSON(t, ts, "/api/v1/checksums", b)
		if errCode(body) != ErrInvalidParameter {
			t.Fatalf("case %d: got %d %v, want code %s", i, status, body, ErrInvalidParameter)
		}
	}

	// profile 与 params 同时给、二者都不给。
	status, body = postJSON(t, ts, "/api/v1/checksums", map[string]any{
		"profile": "CRC-8",
		"params":  map[string]any{"width": 8, "poly": 7, "init": 0, "ref_in": false, "ref_out": false, "xor_out": 0},
		"data":    enc,
	})
	if errCode(body) != ErrProfileAndParams {
		t.Fatalf("got %v", body)
	}
	status, body = postJSON(t, ts, "/api/v1/checksums", map[string]any{"data": enc})
	if errCode(body) != ErrMissingProfile {
		t.Fatalf("got %d %v", status, body)
	}
}

// 所有结构化错误类型的 HTTP 行为。
func TestHTTPErrors(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	enc := base64.StdEncoding.EncodeToString([]byte("123456789"))

	// 未知档名：404 + UNKNOWN_PROFILE，绝不猜测。
	status, body := postJSON(t, ts, "/api/v1/checksums", map[string]any{
		"profile": "CRC-666/HYPOTHETICAL", "data": enc,
	})
	if status != http.StatusNotFound || errCode(body) != ErrUnknownProfile {
		t.Fatalf("got %d %v", status, body)
	}

	// base64 格式错误。
	status, body = postJSON(t, ts, "/api/v1/checksums", map[string]any{
		"profile": "CRC-8", "data": "@@@not base64@@@",
	})
	if status != http.StatusBadRequest || errCode(body) != ErrDataFormat {
		t.Fatalf("got %d %v", status, body)
	}

	// 校验码位数不对 / 非法十六进制。
	status, body = postJSON(t, ts, "/api/v1/verify", map[string]any{
		"profile": "CRC-8", "data": enc, "checksum": "f",
	})
	if errCode(body) != ErrChecksumFormat {
		t.Fatalf("got %d %v", status, body)
	}
	status, body = postJSON(t, ts, "/api/v1/verify", map[string]any{
		"profile": "CRC-8", "data": enc, "checksum": "zz",
	})
	if errCode(body) != ErrChecksumFormat {
		t.Fatalf("got %d %v", status, body)
	}
	status, body = postJSON(t, ts, "/api/v1/verify", map[string]any{
		"profile": "CRC-16/CCITT-FALSE", "data": enc, "checksum": "29b1X",
	})
	if errCode(body) != ErrChecksumFormat {
		t.Fatalf("got %d %v", status, body)
	}

	// engine 非法。
	status, body = postJSON(t, ts, "/api/v1/checksums", map[string]any{
		"profile": "CRC-8", "data": enc, "engine": "fpga",
	})
	if errCode(body) != ErrInvalidEngine {
		t.Fatalf("got %d %v", status, body)
	}

	// JSON 非法 / 未知字段。
	resp, err := http.Post(ts.URL+"/api/v1/checksums", "application/json",
		bytes.NewReader([]byte("{not json")))
	if err != nil {
		t.Fatal(err)
	}
	var eb ErrorResponse
	json.NewDecoder(resp.Body).Decode(&eb)
	resp.Body.Close()
	if eb.Error.Code != ErrInvalidJSON {
		t.Fatalf("got %+v", eb)
	}
	resp, err = http.Post(ts.URL+"/api/v1/checksums", "application/json",
		bytes.NewReader([]byte(`{"profile":"CRC-8","data":"","bogus":1}`)))
	if err != nil {
		t.Fatal(err)
	}
	json.NewDecoder(resp.Body).Decode(&eb)
	resp.Body.Close()
	if eb.Error.Code != ErrInvalidJSON {
		t.Fatalf("unknown field not rejected: %+v", eb)
	}

	// 方法不允许 / 路径不存在。
	resp, _ = http.Get(ts.URL + "/api/v1/checksums")
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET compute status = %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp, _ = http.Get(ts.URL + "/nope")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown path status = %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// 空载荷经服务必须返回确定、非空、定长的十六进制码，且可验证通过。
func TestHTTPEmptyPayload(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	for _, empty := range []string{"", base64.StdEncoding.EncodeToString(nil)} {
		status, body := postJSON(t, ts, "/api/v1/checksums", map[string]any{
			"profile": "CRC-16/CCITT-FALSE", "data": empty,
		})
		if status != 200 || body["check"] != "ffff" {
			t.Fatalf("empty(%q): %d %v", empty, status, body)
		}
		status, vbody := postJSON(t, ts, "/api/v1/verify", map[string]any{
			"profile": "CRC-16/CCITT-FALSE", "data": empty, "checksum": "ffff",
		})
		if status != 200 || vbody["valid"] != true {
			t.Fatalf("empty verify: %d %v", status, vbody)
		}
	}
}

// 经 HTTP 的按位/查表两路同余 + 8/16 位档相异。
func TestHTTPEngineAgreementAndWidthDifference(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	enc := base64.StdEncoding.EncodeToString([]byte("width & engine comparison"))
	get := func(profile, engine string) string {
		req := map[string]any{"profile": profile, "data": enc}
		if engine != "" {
			req["engine"] = engine
		}
		status, body := postJSON(t, ts, "/api/v1/checksums", req)
		if status != 200 {
			t.Fatal(body)
		}
		return body["check"].(string)
	}
	for _, p := range []string{"CRC-8", "CRC-8/MAXIM", "CRC-16/CCITT-FALSE", "CRC-16/KERMIT", "CRC-16/MODBUS", "CRC-32/ISO-HDLC"} {
		if get(p, "table") != get(p, "bitwise") {
			t.Fatalf("%s engines disagree", p)
		}
	}
	if get("CRC-8", "") == get("CRC-16/CCITT-FALSE", "") {
		t.Fatal("8-bit and 16-bit checksums equal")
	}
}

// /metrics 暴露 Prometheus 文本指标，且错误按结构化错误码计数。
func TestHTTPMetrics(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	// 制造一次成功请求和两次不同类型的错误。
	postJSON(t, ts, "/api/v1/checksums", map[string]any{
		"profile": "CRC-8", "data": "",
	})
	postJSON(t, ts, "/api/v1/checksums", map[string]any{
		"profile": "DOES-NOT-EXIST", "data": "",
	})
	postJSON(t, ts, "/api/v1/checksums", map[string]any{
		"profile": "CRC-8", "data": "!!!not-base64!!!",
	})

	resp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("metrics status = %d", resp.StatusCode)
	}
	text := string(body)
	for _, want := range []string{
		"# TYPE crc_http_requests_total counter",
		`crc_http_requests_total{route="/api/v1/checksums",method="POST",status="200"} 1`,
		`code="UNKNOWN_PROFILE"`,
		`code="DATA_FORMAT_ERROR"`,
		"# TYPE crc_http_request_duration_seconds histogram",
		"crc_http_request_duration_seconds_bucket",
		"crc_http_request_duration_seconds_count",
		// /metrics 渲染时其自身仍在飞，in_flight 至少包含当前这次请求。
		"# TYPE crc_requests_in_flight gauge",
		"crc_requests_in_flight ",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics output missing %q\nfull:\n%s", want, text)
		}
	}
}

// 并发打服务：不同档、不同数据、不同引擎混跑，结果必须稳定且可自校验。
func TestHTTPConcurrent(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	profs := crc.ListProfiles()
	var wg sync.WaitGroup
	var firstErr any
	var mu sync.Mutex
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for k := 0; k < 50; k++ {
				prof := profs[(worker+k)%len(profs)]
				raw := []byte(fmt.Sprintf("worker-%d-msg-%d", worker, k))
				enc := base64.StdEncoding.EncodeToString(raw)
				engine := []string{"table", "bitwise"}[(worker+k)%2]
				_, cb := postJSON(t, ts, "/api/v1/checksums", map[string]any{
					"profile": prof.Name, "data": enc, "engine": engine,
				})
				check, ok := cb["check"].(string)
				if !ok {
					mu.Lock()
					firstErr = cb
					mu.Unlock()
					return
				}
				// 再算一次确认无状态、结果确定。
				_, cb2 := postJSON(t, ts, "/api/v1/checksums", map[string]any{
					"profile": prof.Name, "data": enc, "engine": engine,
				})
				if cb2["check"] != check {
					mu.Lock()
					firstErr = fmt.Sprintf("nondeterministic: %s vs %s", check, cb2["check"])
					mu.Unlock()
					return
				}
				_, vb := postJSON(t, ts, "/api/v1/verify", map[string]any{
					"profile": prof.Name, "data": enc, "checksum": check, "engine": engine,
				})
				if vb["valid"] != true {
					mu.Lock()
					firstErr = vb
					mu.Unlock()
					return
				}
			}
		}(i)
	}
	wg.Wait()
	if firstErr != nil {
		t.Fatalf("concurrent failure: %v", firstErr)
	}
}
