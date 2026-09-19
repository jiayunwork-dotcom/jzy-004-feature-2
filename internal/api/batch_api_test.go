package api

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"crcservice/internal/crc"
)

func enc(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// 批量核算：每条结果必须与逐条单独调用单次接口逐位一致；单条失败定位到
// 具体条目与错误码，不波及其余条目。
func TestHTTPBatchMatchesSingleCalls(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	adHoc := map[string]any{
		"width": 12, "poly": "0x80f", "init": "0xabc",
		"ref_in": true, "ref_out": false, "xor_out": "0xfff",
	}
	items := []any{
		map[string]any{"profile": "CRC-8", "data": enc("123456789")},
		map[string]any{"profile": "CRC-32/ISO-HDLC", "data": enc("123456789"), "engine": "bitwise"},
		map[string]any{"params": adHoc, "data": enc("hello world")},
		map[string]any{"profile": "CRC-16/MODBUS", "data": ""}, // 空载荷
		map[string]any{"profile": "CRC-16/KERMIT", "data": enc("\x00\xff\x10binary")},
	}
	status, body := postJSON(t, ts, "/api/v1/checksums/batch", map[string]any{"items": items})
	if status != http.StatusOK {
		t.Fatalf("batch status %d body %v", status, body)
	}
	results, ok := body["results"].([]any)
	if !ok || len(results) != len(items) {
		t.Fatalf("bad results: %v", body)
	}
	for i, item := range items {
		res := results[i].(map[string]any)
		if int(res["index"].(float64)) != i || res["ok"] != true {
			t.Fatalf("item %d: bad result %v", i, res)
		}
		// 与逐条单次调用逐位一致。
		single := item.(map[string]any)
		_, sbody := postJSON(t, ts, "/api/v1/checksums", single)
		if res["check"] != sbody["check"] || res["width"] != sbody["width"] || res["engine"] != sbody["engine"] {
			t.Fatalf("item %d: batch %v != single %v", i, res, sbody)
		}
	}
	// 公开向量值直接出现在批量结果里。
	if results[0].(map[string]any)["check"] != "f4" ||
		results[1].(map[string]any)["check"] != "cbf43926" {
		t.Fatalf("catalog values wrong: %v %v", results[0], results[1])
	}
}

// 批量中的失败条目：定位到下标、给出与单次接口一致的错误码；其余条目正常。
func TestHTTPBatchItemFailuresLocated(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	items := []any{
		map[string]any{"profile": "CRC-8", "data": enc("ok-0")},
		map[string]any{"profile": "CRC-666/NOPE", "data": ""},                     // UNKNOWN_PROFILE
		map[string]any{"profile": "CRC-8", "data": "@@@not-base64@@@"},            // DATA_FORMAT_ERROR
		map[string]any{"data": ""},                                                // MISSING_PROFILE
		map[string]any{"profile": "CRC-8", "data": enc("ok-4"), "engine": "fpga"}, // INVALID_ENGINE
		map[string]any{"params": map[string]any{ // INVALID_PARAMETER（偶数多项式）
			"width": 8, "poly": "0x30", "init": 0, "ref_in": false, "ref_out": false, "xor_out": 0,
		}, "data": ""},
		map[string]any{"profile": "CRC-8", // PROFILE_AND_PARAMS
			"params": map[string]any{"width": 8, "poly": 7, "init": 0, "ref_in": false, "ref_out": false, "xor_out": 0},
			"data":   ""},
		map[string]any{"profile": "CRC-8", "data": enc("ok-7")},
	}
	wantCodes := []string{"", ErrUnknownProfile, ErrDataFormat, ErrMissingProfile,
		ErrInvalidEngine, ErrInvalidParameter, ErrProfileAndParams, ""}

	status, body := postJSON(t, ts, "/api/v1/checksums/batch", map[string]any{"items": items})
	if status != http.StatusOK {
		t.Fatalf("batch with item failures must still return 200, got %d %v", status, body)
	}
	results := body["results"].([]any)
	if len(results) != len(items) {
		t.Fatalf("results len = %d, want %d", len(results), len(items))
	}
	for i, res := range results {
		r := res.(map[string]any)
		if int(r["index"].(float64)) != i {
			t.Fatalf("result %d: index = %v", i, r["index"])
		}
		if wantCodes[i] == "" {
			if r["ok"] != true || r["check"] == nil {
				t.Fatalf("item %d should succeed: %v", i, r)
			}
			continue
		}
		if r["ok"] != false {
			t.Fatalf("item %d should fail: %v", i, r)
		}
		e, ok := r["error"].(map[string]any)
		if !ok || e["code"] != wantCodes[i] || e["detail"] == "" {
			t.Fatalf("item %d: got %v, want code %s with detail", i, r, wantCodes[i])
		}
	}
}

// 批量信封级错误：空批、超上限、非法 JSON、未知字段、方法错误。
func TestHTTPBatchEnvelopeErrors(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	// items 缺失 / 为空。
	for _, body := range []map[string]any{{}, {"items": []any{}}} {
		status, resp := postJSON(t, ts, "/api/v1/checksums/batch", body)
		if status != http.StatusBadRequest || errCode(resp) != ErrBatchEmpty {
			t.Fatalf("empty batch: %d %v", status, resp)
		}
	}
	// 超过单批上限。
	big := make([]any, maxBatchItems+1)
	for i := range big {
		big[i] = map[string]any{"profile": "CRC-8", "data": ""}
	}
	status, resp := postJSON(t, ts, "/api/v1/checksums/batch", map[string]any{"items": big})
	if status != http.StatusUnprocessableEntity || errCode(resp) != ErrBatchTooLarge {
		t.Fatalf("oversized batch: %d %v", status, resp)
	}
	// 恰好达到上限必须成功。
	status, resp = postJSON(t, ts, "/api/v1/checksums/batch", map[string]any{"items": big[:maxBatchItems]})
	if status != http.StatusOK || len(resp["results"].([]any)) != maxBatchItems {
		t.Fatalf("max-size batch: %d %v", status, resp)
	}
	// 条目内未知字段（信封层面 JSON 严格性）。
	status, resp = postJSON(t, ts, "/api/v1/checksums/batch", map[string]any{
		"items": []any{map[string]any{"profile": "CRC-8", "data": "", "bogus": 1}},
	})
	if status != http.StatusBadRequest || errCode(resp) != ErrInvalidJSON {
		t.Fatalf("unknown item field: %d %v", status, resp)
	}
	// 方法错误。
	r, err := http.Get(ts.URL + "/api/v1/checksums/batch")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET batch = %d", r.StatusCode)
	}
	// 非法 JSON。
	r, err = http.Post(ts.URL+"/api/v1/checksums/batch", "application/json", strings.NewReader("{nope"))
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad json batch = %d", r.StatusCode)
	}
}

// 批量与单次接口共享参数解析：显式临时档与同名具名档结果一致；
// 批量单条退化等价于单次调用。
func TestHTTPBatchSharedSemantics(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	data := enc("shared semantics probe")
	// 显式临时档 == 具名档 CRC-16/CCITT-FALSE。
	status, body := postJSON(t, ts, "/api/v1/checksums/batch", map[string]any{
		"items": []any{
			map[string]any{"profile": "CRC-16/CCITT-FALSE", "data": data},
			map[string]any{"params": map[string]any{
				"width": 16, "poly": "0x1021", "init": "0xffff",
				"ref_in": false, "ref_out": false, "xor_out": "0x0",
			}, "data": data},
		},
	})
	if status != http.StatusOK {
		t.Fatalf("%d %v", status, body)
	}
	results := body["results"].([]any)
	c0 := results[0].(map[string]any)["check"]
	c1 := results[1].(map[string]any)["check"]
	if c1 != c0 {
		t.Fatalf("named vs ad-hoc in batch disagree: %v vs %v", c0, c1)
	}
	// 单条批量 == 单次接口。
	_, single := postJSON(t, ts, "/api/v1/checksums", map[string]any{"profile": "CRC-16/CCITT-FALSE", "data": data})
	if c0 != single["check"] {
		t.Fatalf("batch of one %v != single %v", c0, single["check"])
	}
	// 具名档对公开向量的批量结果仍等于 catalog 值。
	_, vb := postJSON(t, ts, "/api/v1/checksums/batch", map[string]any{
		"items": []any{map[string]any{"profile": "CRC-16/CCITT-FALSE", "data": enc("123456789")}},
	})
	if vb["results"].([]any)[0].(map[string]any)["check"] != "29b1" {
		t.Fatalf("catalog vector in batch wrong: %v", vb)
	}
}

// 批量接口在并发下结果确定（无状态、无串扰），覆盖多条目混合负载。
func TestHTTPBatchConcurrent(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	profs := crc.ListProfiles()
	done := make(chan string, 8)
	for w := 0; w < 8; w++ {
		go func(worker int) {
			defer func() { done <- "" }()
			for k := 0; k < 15; k++ {
				var items []any
				var wants []string
				for j := 0; j < 6; j++ {
					prof := profs[(worker+k+j)%len(profs)]
					payload := fmt.Sprintf("w%d-k%d-j%d", worker, k, j)
					items = append(items, map[string]any{"profile": prof.Name, "data": enc(payload)})
					_, sb := postJSON(t, ts, "/api/v1/checksums", map[string]any{
						"profile": prof.Name, "data": enc(payload),
					})
					wants = append(wants, sb["check"].(string))
				}
				_, bb := postJSON(t, ts, "/api/v1/checksums/batch", map[string]any{"items": items})
				results := bb["results"].([]any)
				for j, res := range results {
					if res.(map[string]any)["check"] != wants[j] {
						t.Errorf("worker %d iter %d item %d: batch %v != single %v",
							worker, k, j, res, wants[j])
						return
					}
				}
			}
		}(w)
	}
	for w := 0; w < 8; w++ {
		<-done
	}
}
