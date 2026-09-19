package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"crcservice/internal/crc"
)

// Version 是服务版本号。
const Version = "1.1.0"

// Server 持有运行期只读状态。计算本身无状态：所有中间余数都是请求内局部
// 变量，注册表启动后只读，因此并发请求之间不会有任何串扰。
// stateKey 用于签发/校验流式状态令牌（HMAC 密钥，属配置而非会话状态）。
type Server struct {
	startedAt time.Time
	stateKey  []byte
	metrics   *metricsRegistry
	mux       *http.ServeMux
}

// NewServer 构建带全部路由的服务。流式状态令牌的密钥取 CRC_STATE_KEY；
// 未配置时使用进程级随机密钥（见 stateKeyFromEnv）。
func NewServer() *Server {
	return newServerWithKey(stateKeyFromEnv())
}

// newServerWithKey 用指定的流式状态密钥构建服务（测试与多实例部署用）。
func newServerWithKey(stateKey []byte) *Server {
	s := &Server{
		startedAt: time.Now(),
		stateKey:  stateKey,
		metrics:   newMetrics(),
		mux:       http.NewServeMux(),
	}
	s.mux.HandleFunc("/healthz", s.handleHealth)
	s.mux.HandleFunc("/metrics", s.handleMetrics)
	s.mux.HandleFunc("/api/v1/profiles", s.handleProfiles)
	s.mux.HandleFunc("/api/v1/vectors", s.handleVectors)
	s.mux.HandleFunc("/api/v1/checksums", s.handleChecksums)
	s.mux.HandleFunc("/api/v1/checksums/batch", s.handleBatch)
	s.mux.HandleFunc("/api/v1/stream", s.handleStream)
	s.mux.HandleFunc("/api/v1/verify", s.handleVerify)
	s.mux.HandleFunc("/", s.handleNotFound)
	return s
}

// Handler 暴露给外层 HTTP server。
func (s *Server) Handler() http.Handler {
	return s.metricsMiddleware(s.mux)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, detail string) {
	if rec, ok := w.(*statusRecorder); ok {
		rec.errCode = code
	}
	writeJSON(w, status, ErrorResponse{Error: ErrorBody{Code: code, Detail: detail}})
}

// decodeBody 严格解析 JSON：拒绝空体、语法错误及未知字段。
func decodeBody(w http.ResponseWriter, r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("body must contain a single JSON object")
		}
		return err
	}
	return nil
}

// resolveParams 统一处理“具名档 / 显式临时档”二选一，并在计算之前完成
// 全部输入校验。返回生效的参数档、档名（临时档为空串）与可直接回显的错误
// （含建议的 HTTP 状态码）。
func resolveParams(profileName string, dto *ParamsDTO) (crc.Params, string, int, string, string) {
	if profileName != "" && dto != nil {
		return crc.Params{}, "", http.StatusBadRequest, ErrProfileAndParams,
			"provide either 'profile' or 'params', not both"
	}
	if profileName == "" && dto == nil {
		return crc.Params{}, "", http.StatusBadRequest, ErrMissingProfile,
			"either 'profile' or 'params' is required"
	}
	if profileName != "" {
		prof, err := crc.GetProfile(profileName)
		if err != nil {
			return crc.Params{}, "", http.StatusNotFound, ErrUnknownProfile,
				"profile '" + profileName + "' is not registered; " +
					"query GET /api/v1/profiles for available names"
		}
		return prof.Params, prof.Name, 0, "", ""
	}
	// 显式临时档：五个字段全部必填，避免隐式默认值悄悄改变 CRC 约定。
	missing := ""
	if dto.Width == nil {
		missing = "width"
	} else if dto.Poly == nil {
		missing = "poly"
	} else if dto.Init == nil {
		missing = "init"
	} else if dto.RefIn == nil {
		missing = "ref_in"
	} else if dto.RefOut == nil {
		missing = "ref_out"
	} else if dto.XorOut == nil {
		missing = "xor_out"
	}
	if missing != "" {
		return crc.Params{}, "", http.StatusBadRequest, ErrInvalidParameter,
			"params." + missing + " is required when constructing an ad-hoc profile"
	}
	p := crc.Params{
		Width:  uint8(*dto.Width),
		Poly:   uint64(*dto.Poly),
		Init:   uint64(*dto.Init),
		RefIn:  *dto.RefIn,
		RefOut: *dto.RefOut,
		XorOut: uint64(*dto.XorOut),
	}
	if err := p.Validate(); err != nil {
		return crc.Params{}, "", http.StatusUnprocessableEntity, ErrInvalidParameter, err.Error()
	}
	return p, "", 0, "", ""
}

// resolveEngine 解析除法路径选择。
func resolveEngine(name string) (crc.Engine, string, string) {
	eng, ok := crc.ParseEngine(name)
	if !ok {
		return "", ErrInvalidEngine,
			"engine must be 'table' or 'bitwise' (default 'table')"
	}
	return eng, "", ""
}

// decodeData 按服务固定的载荷格式（标准 base64 带填充）解码；
// 任何不合规都在计算前报格式错误。
func decodeData(s string) ([]byte, int, string, string) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, http.StatusBadRequest, ErrDataFormat,
			"'data' must be standard base64 (RFC 4648, padded); " + err.Error()
	}
	return b, 0, "", ""
}
