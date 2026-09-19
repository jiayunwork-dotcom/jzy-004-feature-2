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
			"POST /api/v1/checksums, POST /api/v1/checksums/batch, "+
			"POST /api/v1/chunks, POST /api/v1/verify")
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
