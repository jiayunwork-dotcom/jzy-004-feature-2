package api

import (
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"net/http"
	"strings"
	"testing"

	"crcservice/internal/crc"
)

// 批量与逐条一致：每条结果必须与单独调用单次编码接口逐位一致。
// 覆盖全部内置档、显式临时档、空载荷、逐条引擎覆盖与整批默认引擎。
func TestHTTPBatchMatchesOneShot(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	rng := rand.New(rand.NewSource(60606))

	var items []map[string]any
	// 全部内置档 × 多种载荷（含空载荷与二进制数据）。
	payloads := [][]byte{nil, []byte("123456789"), []byte("batch payload"), make([]byte, 257)}
	rng.Read(payloads[3])
	for _, prof := range crc.ListProfiles() {
		for _, raw := range payloads {
			items = append(items, map[string]any{
				"profile": prof.Name,
				"data":    base64.StdEncoding.EncodeToString(raw),
			})
		}
	}
	// 显式临时档（含非字节宽度与 xor_out 非零）。
	adHoc := map[string]any{
		"width": 13, "poly": "0x1f35", "init": "0x1ff",
		"ref_in": true, "ref_out": false, "xor_out": "0x1c2",
	}
	items = append(items, map[string]any{"params": adHoc, "data": base64.StdEncoding.EncodeToString([]byte("ad-hoc"))})
	// 逐条引擎覆盖。
	items = append(items, map[string]any{"profile": "CRC-8", "data": "", "engine": "bitwise"})

	// 整批默认引擎 bitwise，逐条未指定者用它。
	status, body := postJSON(t, ts, "/api/v1/checksums/batch", map[string]any{
		"engine": "bitwise", "items": items,
	})
	if status != http.StatusOK {
		t.Fatalf("batch status %d body %v", status, body)
	}
	results, _ := body["results"].([]any)
	if len(results) != len(items) {
		t.Fatalf("got %d results for %d items", len(results), len(items))
	}

	for i, item := range items {
		r := results[i].(map[string]any)
		if int(r["index"].(float64)) != i || r["ok"] != true {
			t.Fatalf("item %d: bad result envelope %v", i, r)
		}
		// 与逐条单次调用逐位一致（引擎语义一致：默认被整批覆盖为 bitwise）。
		single := map[string]any{}
		for k, v := range item {
			single[k] = v
		}
		if _, has := single["engine"]; !has {
			single["engine"] = "bitwise"
		}
		want := oneShot(t, ts, single)
		if r["check"] != want {
			t.Fatalf("item %d: batch check %v != one-shot %s", i, r["check"], want)
		}
		if eng, _ := single["engine"].(string); r["engine"] != eng {
			t.Fatalf("item %d: engine %v != %s", i, r["engine"], eng)
		}
	}
}

// 单条失败定位：批量中混入各类非法条目，每条失败都必须带 index 与结构化
// 错误码，且不影响其它条目正常出结果；整体仍返回 200。
func TestHTTPBatchItemFailuresLocalized(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	enc := base64.StdEncoding.EncodeToString([]byte("123456789"))

	items := []map[string]any{
		{"profile": "CRC-8", "data": enc},                   // 0 ok
		{"profile": "CRC-666/NOPE", "data": enc},            // 1 UNKNOWN_PROFILE
		{"profile": "CRC-16/KERMIT", "data": "@@not-b64@@"}, // 2 DATA_FORMAT_ERROR
		{"params": map[string]any{"width": 4, "poly": 3, "init": 0, "ref_in": false, "ref_out": false, "xor_out": 0}, "data": enc},                     // 3 INVALID_PARAMETER
		{"profile": "CRC-8", "params": map[string]any{"width": 8, "poly": 7, "init": 0, "ref_in": false, "ref_out": false, "xor_out": 0}, "data": enc}, // 4 PROFILE_AND_PARAMS
		{"data": enc}, // 5 MISSING_PROFILE
		{"profile": "CRC-8", "data": enc, "engine": "warp"}, // 6 INVALID_ENGINE
		{"profile": "CRC-32/ISO-HDLC", "data": enc},         // 7 ok
	}
	wantCodes := map[int]string{
		1: ErrUnknownProfile,
		2: ErrDataFormat,
		3: ErrInvalidParameter,
		4: ErrProfileAndParams,
		5: ErrMissingProfile,
		6: ErrInvalidEngine,
	}

	status, body := postJSON(t, ts, "/api/v1/checksums/batch", map[string]any{"items": items})
	if status != http.StatusOK {
		t.Fatalf("batch with bad items must still return 200, got %d %v", status, body)
	}
	results, _ := body["results"].([]any)
	if len(results) != len(items) {
		t.Fatalf("got %d results for %d items", len(results), len(items))
	}
	for i, r := range results {
		res := r.(map[string]any)
		if int(res["index"].(float64)) != i {
			t.Fatalf("result %d has index %v", i, res["index"])
		}
		if code, bad := wantCodes[i]; bad {
			if res["ok"] != false {
				t.Fatalf("item %d should fail: %v", i, res)
			}
			e, _ := res["error"].(map[string]any)
			if e["code"] != code {
				t.Fatalf("item %d: error code %v, want %s (detail %v)", i, e["code"], code, e["detail"])
			}
			if e["detail"] == "" {
				t.Fatalf("item %d: error detail empty", i)
			}
			continue
		}
		if res["ok"] != true {
			t.Fatalf("item %d should succeed: %v", i, res)
		}
		// 成功条目与单次接口一致。
		if res["check"] != oneShot(t, ts, items[i]) {
			t.Fatalf("item %d: batch %v != one-shot", i, res["check"])
		}
	}
}

// 批量信封级错误：缺 items、超上限、整批引擎非法、JSON 非法、方法错误。
func TestHTTPBatchEnvelopeErrors(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	enc := base64.StdEncoding.EncodeToString([]byte("x"))

	// 缺 items。
	status, body := postJSON(t, ts, "/api/v1/checksums/batch", map[string]any{})
	if status != http.StatusBadRequest || errCode(body) != ErrInvalidParameter {
		t.Fatalf("missing items: %d %v", status, body)
	}

	// 空 items 合法：返回空结果集。
	status, body = postJSON(t, ts, "/api/v1/checksums/batch", map[string]any{"items": []any{}})
	if status != http.StatusOK {
		t.Fatalf("empty items: %d %v", status, body)
	}
	if results, _ := body["results"].([]any); len(results) != 0 {
		t.Fatalf("empty items should give empty results: %v", body)
	}

	// 超上限。
	big := make([]map[string]any, maxBatchItems+1)
	for i := range big {
		big[i] = map[string]any{"profile": "CRC-8", "data": enc}
	}
	status, body = postJSON(t, ts, "/api/v1/checksums/batch", map[string]any{"items": big})
	if status != http.StatusBadRequest || errCode(body) != ErrInvalidParameter {
		t.Fatalf("oversized batch: %d %v", status, body)
	}

	// 整批默认引擎非法（信封级，整体拒绝）。
	status, body = postJSON(t, ts, "/api/v1/checksums/batch", map[string]any{
		"engine": "quantum", "items": []map[string]any{{"profile": "CRC-8", "data": enc}},
	})
	if status != http.StatusBadRequest || errCode(body) != ErrInvalidEngine {
		t.Fatalf("bad batch engine: %d %v", status, body)
	}

	// JSON 非法 / 未知字段。
	resp, err := http.Post(ts.URL+"/api/v1/checksums/batch", "application/json", strings.NewReader("{nope"))
	if err != nil {
		t.Fatal(err)
	}
	var eb ErrorResponse
	decodeJSONBody(resp, &eb)
	if eb.Error.Code != ErrInvalidJSON {
		t.Fatalf("invalid json: %+v", eb)
	}
	resp, err = http.Post(ts.URL+"/api/v1/checksums/batch", "application/json",
		strings.NewReader(`{"items":[],"bogus":1}`))
	if err != nil {
		t.Fatal(err)
	}
	decodeJSONBody(resp, &eb)
	if eb.Error.Code != ErrInvalidJSON {
		t.Fatalf("unknown field: %+v", eb)
	}

	// 方法错误。
	resp, err = http.Get(ts.URL + "/api/v1/checksums/batch")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET batch = %d", resp.StatusCode)
	}
}

// 大批量确定性与并发安全：1024 条混合条目一次算完，结果与本地参考一致。
func TestHTTPBatchLargeAndConcurrent(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	profs := crc.ListProfiles()
	rng := rand.New(rand.NewSource(112233))

	items := make([]map[string]any, maxBatchItems)
	want := make([]string, maxBatchItems)
	for i := range items {
		p := profs[rng.Intn(len(profs))]
		d := make([]byte, rng.Intn(64))
		rng.Read(d)
		items[i] = map[string]any{"profile": p.Name, "data": base64.StdEncoding.EncodeToString(d)}
		want[i] = crc.FormatHex(crc.Compute(p.Params, d, crc.EngineTable), p.Params.Width)
	}

	// 并发提交 4 批，结果必须一致。
	type outcome struct {
		results []string
		ok      bool
	}
	ch := make(chan outcome, 4)
	for k := 0; k < 4; k++ {
		go func() {
			resp, err := http.Post(ts.URL+"/api/v1/checksums/batch", "application/json",
				strings.NewReader(mustJSON(map[string]any{"items": items})))
			if err != nil {
				ch <- outcome{}
				return
			}
			defer resp.Body.Close()
			var body struct {
				Results []struct {
					OK    bool   `json:"ok"`
					Check string `json:"check"`
				} `json:"results"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || resp.StatusCode != 200 {
				ch <- outcome{}
				return
			}
			got := make([]string, len(body.Results))
			for i, r := range body.Results {
				if !r.OK {
					ch <- outcome{}
					return
				}
				got[i] = r.Check
			}
			ch <- outcome{results: got, ok: true}
		}()
	}
	for k := 0; k < 4; k++ {
		o := <-ch
		if !o.ok {
			t.Fatal("concurrent batch failed")
		}
		for i := range want {
			if o.results[i] != want[i] {
				t.Fatalf("item %d: batch %s != reference %s", i, o.results[i], want[i])
			}
		}
	}
}

// decodeJSONBody 解析响应体并关闭。
func decodeJSONBody(resp *http.Response, v any) {
	defer resp.Body.Close()
	_ = json.NewDecoder(resp.Body).Decode(v)
}
