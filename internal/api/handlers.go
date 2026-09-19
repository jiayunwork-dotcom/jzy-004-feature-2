package api

import (
	"encoding/base64"
	"net/http"
	"strconv"
	"time"

	"crcservice/internal/crc"
)

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotFound, ErrNotFound,
		"unknown path "+r.URL.Path+
			"; available: GET /healthz, GET /api/v1/profiles, GET /api/v1/vectors, "+
			"POST /api/v1/checksums, POST /api/v1/checksums/batch, POST /api/v1/stream, "+
			"POST /api/v1/verify")
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, ErrMethodNotAllowed, "use GET")
		return
	}
	now := time.Now()
	writeJSON(w, http.StatusOK, HealthResponse{
		Status:        "ok",
		Version:       Version,
		Profiles:      len(crc.ListProfiles()),
		UpSince:       s.startedAt.UTC(),
		UptimeSeconds: int64(now.Sub(s.startedAt).Seconds()),
	})
}

// profileView 是 /profiles 返回的单档视图，完整展开所有约定。
type profileView struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Params      crc.Params `json:"params"`
	Check       string     `json:"check_123456789"` // 公开向量「123456789」标准余数
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, ErrMethodNotAllowed, "use GET")
		return
	}
	profs := crc.ListProfiles()
	views := make([]profileView, 0, len(profs))
	for _, p := range profs {
		views = append(views, profileView{
			Name:        p.Name,
			Description: p.Description,
			Params:      p.Params,
			Check:       crc.FormatHex(p.Check, p.Params.Width),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": views})
}

func (s *Server) handleVectors(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, ErrMethodNotAllowed, "use GET")
		return
	}
	profs := crc.ListProfiles()
	vecs := make([]Vector, 0, len(profs))
	for _, p := range profs {
		vecs = append(vecs, Vector{
			Profile:     p.Name,
			InputASCII:  "123456789",
			InputBase64: base64.StdEncoding.EncodeToString(crc.StandardVector),
			ExpectedHex: crc.FormatHex(p.Check, p.Params.Width),
			Width:       p.Params.Width,
			Source:      "CRC RevEng catalogue (https://reveng.sourceforge.io/crc-catalogue/)",
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"vectors": vecs})
}

func (s *Server) handleChecksums(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, ErrMethodNotAllowed, "use POST")
		return
	}
	var req ComputeRequest
	if err := decodeBody(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, ErrInvalidJSON, "request body must be one JSON object: "+err.Error())
		return
	}
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
	data, status, errCode, detail := decodeData(req.Data)
	if errCode != "" {
		writeError(w, status, errCode, detail)
		return
	}
	// 纯函数式计算：所有中间量都是本次请求的局部状态。
	check := crc.Compute(params, data, engine)
	writeJSON(w, http.StatusOK, ChecksumResponse{
		Profile: profName,
		Width:   params.Width,
		Check:   crc.FormatHex(check, params.Width),
		Engine:  string(engine),
	})
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, ErrMethodNotAllowed, "use POST")
		return
	}
	var req VerifyRequest
	if err := decodeBody(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, ErrInvalidJSON, "request body must be one JSON object: "+err.Error())
		return
	}
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
	data, status, errCode, detail := decodeData(req.Data)
	if errCode != "" {
		writeError(w, status, errCode, detail)
		return
	}
	if req.Checksum == "" {
		writeError(w, http.StatusBadRequest, ErrChecksumFormat,
			"'checksum' is required and must be a zero-padded hexadecimal string of "+
				"exact width "+strconv.Itoa(crc.HexDigits(params.Width))+" digits")
		return
	}
	check, err := crc.ParseHex(req.Checksum, params.Width)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, ErrChecksumFormat,
			"'checksum' must be a hexadecimal string of exactly "+
				strconv.Itoa(crc.HexDigits(params.Width))+" digits within width "+
				strconv.Itoa(int(params.Width))+" bits: "+err.Error())
		return
	}
	residual, valid := crc.Verify(params, data, check, engine)
	writeJSON(w, http.StatusOK, VerifyResponse{
		Profile:  profName,
		Width:    params.Width,
		Valid:    valid,
		Residual: crc.FormatHex(residual, params.Width),
		Engine:   string(engine),
	})
}

// handleStream 推进一次分块流式核算。服务端不保存任何会话：中间状态全部
// 在调用方回传的防篡改令牌里，本处理函数是「状态 + 分块 → 新状态」的纯函数。
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, ErrMethodNotAllowed, "use POST")
		return
	}
	var req StreamRequest
	if err := decodeBody(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, ErrInvalidJSON, "request body must be one JSON object: "+err.Error())
		return
	}

	// 确定本次计算的参数档与起始中间状态：要么从已认证令牌恢复（续传），
	// 要么按首个分块显式给定（与单次接口同一套解析与错误语义）。
	var (
		params   crc.Params
		profName string
		st       streamState
	)
	if req.State != "" {
		var err error
		st, err = decodeStreamState(req.State, s.stateKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, ErrStateInvalid,
				"'state' is not a valid stream state token (unparseable, tampered, or issued under a different key)")
			return
		}
		params, profName = st.params, st.profile
		// 续传时若同时给出 profile/params，必须与令牌内已认证的参数档一致，
		// 防止「拿着 A 档的进度按 B 档继续算」。
		if req.Profile != "" || req.Params != nil {
			p2, name2, status, errCode, detail := resolveParams(req.Profile, req.Params)
			if errCode != "" {
				writeError(w, status, errCode, detail)
				return
			}
			if p2 != params {
				writeError(w, http.StatusConflict, ErrStateMismatch,
					"request profile/params do not match the parameters bound to 'state'; "+
						"continue the stream with its original parameters or start a new one")
				return
			}
			if name2 != "" {
				profName = name2
			}
		}
	} else {
		p, name, status, errCode, detail := resolveParams(req.Profile, req.Params)
		if errCode != "" {
			writeError(w, status, errCode, detail)
			return
		}
		params, profName = p, name
		st = streamState{params: p, profile: name, offset: 0, register: crc.InitRegister(p)}
	}

	engine, errCode, detail := resolveEngine(req.Engine)
	if errCode != "" {
		writeError(w, http.StatusBadRequest, errCode, detail)
		return
	}

	// 分块定位：偏移必须恰好等于已认证的下一偏移。乱序或重复提交的分块
	// 无法安放，明确拒绝（期望偏移在 detail 中给出，调用方可据此重排）。
	offset := uint64(0)
	if req.Offset != nil {
		offset = *req.Offset
	}
	if offset != st.offset {
		writeError(w, http.StatusConflict, ErrStateMismatch,
			"chunk at offset "+strconv.FormatUint(offset, 10)+" cannot be placed: stream expects next offset "+
				strconv.FormatUint(st.offset, 10)+" (out-of-order or duplicate chunk)")
		return
	}

	data, status, errCode, detail := decodeData(req.Data)
	if errCode != "" {
		writeError(w, status, errCode, detail)
		return
	}

	// 纯函数推进：init/xor_out/反射只由首块的 InitRegister 与末块的
	// FinalizeRegister 各作用一次，分块边界无任何额外作用。
	reg := crc.AdvanceRegister(params, st.register, data, engine)
	next := st.offset + uint64(len(data))

	resp := StreamResponse{
		Profile:    profName,
		Width:      params.Width,
		Engine:     string(engine),
		Offset:     st.offset,
		Length:     len(data),
		NextOffset: next,
		Final:      req.Final,
	}
	if req.Final {
		resp.Check = crc.FormatHex(crc.FinalizeRegister(params, reg), params.Width)
	} else {
		resp.State = encodeStreamState(streamState{
			params: params, profile: profName, offset: next, register: reg,
		}, s.stateKey)
	}
	writeJSON(w, http.StatusOK, resp)
}

// maxBatchItems 是单次批量核算的条数上限，约束单请求的计算量。
const maxBatchItems = 1024

// handleBatch 一次请求核算多条 (参数档或临时档, 载荷) 组合。请求本身合法
// 时整体恒返回 200，每条各自给出结果或定位到条目的结构化错误。
func (s *Server) handleBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, ErrMethodNotAllowed, "use POST")
		return
	}
	var req BatchRequest
	if err := decodeBody(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, ErrInvalidJSON, "request body must be one JSON object: "+err.Error())
		return
	}
	if req.Items == nil {
		writeError(w, http.StatusBadRequest, ErrInvalidParameter,
			"'items' is required and must be an array of {profile|params, data} entries")
		return
	}
	if len(req.Items) > maxBatchItems {
		writeError(w, http.StatusBadRequest, ErrInvalidParameter,
			"too many items: "+strconv.Itoa(len(req.Items))+" exceeds the per-request limit of "+
				strconv.Itoa(maxBatchItems))
		return
	}
	defaultEngine, errCode, detail := resolveEngine(req.Engine)
	if errCode != "" {
		writeError(w, http.StatusBadRequest, errCode, detail)
		return
	}

	results := make([]BatchItemResult, len(req.Items))
	for i, item := range req.Items {
		results[i] = computeBatchItem(item, defaultEngine, i)
	}
	writeJSON(w, http.StatusOK, BatchResponse{Results: results})
}

// computeBatchItem 核算批量中的一条。参数解析、格式校验、错误码与单次
// 编码接口完全共用，因此每条结果与逐条调用单次接口逐位一致。
func computeBatchItem(item BatchItemRequest, defaultEngine crc.Engine, index int) BatchItemResult {
	res := BatchItemResult{Index: index}
	fail := func(code, detail string) BatchItemResult {
		res.Error = &ErrorBody{Code: code, Detail: detail}
		return res
	}
	params, profName, _, errCode, detail := resolveParams(item.Profile, item.Params)
	if errCode != "" {
		return fail(errCode, detail)
	}
	engine := defaultEngine
	if item.Engine != "" {
		eng, errCode, detail := resolveEngine(item.Engine)
		if errCode != "" {
			return fail(errCode, detail)
		}
		engine = eng
	}
	data, _, errCode, detail := decodeData(item.Data)
	if errCode != "" {
		return fail(errCode, detail)
	}
	check := crc.Compute(params, data, engine)
	res.OK = true
	res.Profile = profName
	res.Width = params.Width
	res.Check = crc.FormatHex(check, params.Width)
	res.Engine = string(engine)
	return res
}
