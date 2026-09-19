package api

import (
	"net/http"
	"strconv"

	"crcservice/internal/crc"
)

// maxBatchItems 是单个批量请求的条目上限，避免一次请求占用过长的计算时间。
const maxBatchItems = 256

// handleChunks 实现分块流式核算：在给定中间状态上吃掉一个分块、吐出新的
// 中间状态。服务不保存任何会话进度，全部跨块状态都在调用方回传的令牌里。
func (s *Server) handleChunks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, ErrMethodNotAllowed, "use POST")
		return
	}
	var req ChunkRequest
	if err := decodeBody(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, ErrInvalidJSON, "request body must be one JSON object: "+err.Error())
		return
	}
	// 与单次接口完全相同的解析与前置校验：参数档、引擎、载荷格式。
	params, profName, status, errCode, detail := resolveParams(req.Profile, req.Params)
	if errCode != "" {
		writeError(w, status, errCode, detail)
		return
	}
	engine, errCode, detail := resolveEngine(req.Engine)
	if errCode != "" {
		writeError(w, http.StatusBadRequest, errCode, detail)
		return
	}
	if req.Offset == nil {
		writeError(w, http.StatusBadRequest, ErrInvalidParameter,
			"'offset' is required: byte position of this chunk within the whole stream (0 for the first chunk)")
		return
	}
	offset := uint64(*req.Offset)
	data, status, errCode, detail := decodeData(req.Data)
	if errCode != "" {
		writeError(w, status, errCode, detail)
		return
	}

	// 恢复流位置：首块从该参数档的起始寄存器开始（init 只在此生效一次）；
	// 后续块从调用方回传的令牌恢复。令牌的完整性、参数档一致性、偏移连续性
	// 全部在任何计算之前校验。
	var reg uint64
	if req.State == "" {
		if offset != 0 {
			writeError(w, http.StatusUnprocessableEntity, ErrStateOffset,
				"first chunk (no 'state') must have offset 0, got "+
					strconv.FormatUint(offset, 10))
			return
		}
		reg = crc.Begin(params)
	} else {
		st, err := s.decodeState(req.State)
		if err != nil {
			writeError(w, http.StatusBadRequest, ErrStateFormat,
				"'state' is not a valid stream token (malformed or integrity check failed); "+
					"pass back the 'state' value from the previous chunk response verbatim")
			return
		}
		if st.params != paramsFingerprint(params) {
			writeError(w, http.StatusUnprocessableEntity, ErrStateParams,
				"'state' belongs to a different parameter profile; "+
					"all chunks of one stream must use identical profile/params")
			return
		}
		if st.offset != offset {
			writeError(w, http.StatusUnprocessableEntity, ErrStateOffset,
				"chunk cannot be placed: stream is at offset "+
					strconv.FormatUint(st.offset, 10)+" but this chunk declares offset "+
					strconv.FormatUint(offset, 10)+
					"; chunks must be applied in order (re-sending the same chunk "+
					"with the state it was issued for is safe and idempotent)")
			return
		}
		reg = st.reg
	}

	// 纯函数式推进：吃掉这一块、吐出新状态。重传同一 (state, offset, data)
	// 得到完全相同的结果，天然幂等。
	reg = crc.Advance(params, reg, data, engine)
	next := offset + uint64(len(data))
	if next < offset { // 偏移溢出防御（受请求体大小限制实际不可达）
		writeError(w, http.StatusUnprocessableEntity, ErrInvalidParameter, "stream offset overflow")
		return
	}
	resp := ChunkResponse{
		Profile:    profName,
		Width:      params.Width,
		Engine:     string(engine),
		Offset:     offset,
		NextOffset: next,
		Bytes:      len(data),
		State: s.encodeState(streamState{
			offset: next,
			reg:    reg,
			params: paramsFingerprint(params),
		}),
	}
	// final：输出反转与 xor_out 只在此处对整段数据生效一次，结果与把整段
	// 数据一次性交给 POST /api/v1/checksums 逐位相同。
	if req.Final {
		resp.Check = crc.FormatHex(crc.Finalize(params, reg), params.Width)
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleChecksumsBatch 实现批量核算：一次请求计算多条独立载荷各自的校验码。
// 单条失败只影响该条目（结果里给出下标与结构化错误码），不波及其余条目。
func (s *Server) handleChecksumsBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, ErrMethodNotAllowed, "use POST")
		return
	}
	var req BatchRequest
	if err := decodeBody(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, ErrInvalidJSON, "request body must be one JSON object: "+err.Error())
		return
	}
	if len(req.Items) == 0 {
		writeError(w, http.StatusBadRequest, ErrBatchEmpty,
			"'items' is required and must contain at least one entry")
		return
	}
	if len(req.Items) > maxBatchItems {
		writeError(w, http.StatusUnprocessableEntity, ErrBatchTooLarge,
			"too many items: got "+strconv.Itoa(len(req.Items))+
				", max "+strconv.Itoa(maxBatchItems)+" per request")
		return
	}
	results := make([]BatchResult, 0, len(req.Items))
	for i, item := range req.Items {
		results = append(results, computeOne(i, item))
	}
	writeJSON(w, http.StatusOK, BatchResponse{Results: results})
}

// computeOne 用与单次编码接口完全相同的参数解析、格式校验与错误码语义
// 计算一个批量条目；任何失败都定位到该条目本身。
func computeOne(index int, item ComputeRequest) BatchResult {
	fail := func(code, detail string) BatchResult {
		return BatchResult{Index: index, Error: &ErrorBody{Code: code, Detail: detail}}
	}
	params, profName, _, errCode, detail := resolveParams(item.Profile, item.Params)
	if errCode != "" {
		return fail(errCode, detail)
	}
	engine, errCode, detail := resolveEngine(item.Engine)
	if errCode != "" {
		return fail(errCode, detail)
	}
	data, _, errCode, detail := decodeData(item.Data)
	if errCode != "" {
		return fail(errCode, detail)
	}
	check := crc.Compute(params, data, engine)
	return BatchResult{
		Index:   index,
		OK:      true,
		Profile: profName,
		Width:   params.Width,
		Check:   crc.FormatHex(check, params.Width),
		Engine:  string(engine),
	}
}
