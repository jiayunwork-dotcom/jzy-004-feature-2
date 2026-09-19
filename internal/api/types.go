// Package api 实现 CRC 核算服务的 HTTP/JSON 接口。
//
// 载荷编码格式固定为标准 base64（RFC 4648，带填充，即 Go encoding/base64
// 的 StdEncoding）。空字符串表示空载荷，属于合法输入，不按错误处理。
package api

import "time"

// 结构化错误类型。所有非法输入都返回 200 之外的合适 HTTP 状态码，
// 并在 body 中以统一结构区分错误类型，便于上游程序化处理。
const (
	ErrInvalidJSON      = "INVALID_JSON"          // 请求体不是合法 JSON / 含未知字段
	ErrProfileAndParams = "PROFILE_AND_PARAMS"    // 同时给了 profile 与显式 params
	ErrMissingProfile   = "MISSING_PROFILE"       // profile 与 params 都未给出
	ErrUnknownProfile   = "UNKNOWN_PROFILE"       // 引用了未登记的档名
	ErrInvalidParameter = "INVALID_PARAMETER"     // 显式参数越界或非法
	ErrInvalidEngine    = "INVALID_ENGINE"        // engine 取值不支持
	ErrDataFormat       = "DATA_FORMAT_ERROR"     // data 不是合法标准 base64
	ErrChecksumFormat   = "CHECKSUM_FORMAT_ERROR" // checksum 十六进制格式/位数不对
	ErrStateFormat      = "STATE_FORMAT_ERROR"    // state 令牌无法解码或未通过完整性校验
	ErrStateParams      = "STATE_PARAMS_MISMATCH" // state 令牌属于另一个参数档
	ErrStateOffset      = "STATE_OFFSET_MISMATCH" // 分块偏移与流位置不符（乱序/错位）
	ErrBatchEmpty       = "BATCH_EMPTY"           // 批量请求 items 缺失或为空
	ErrBatchTooLarge    = "BATCH_TOO_LARGE"       // 批量请求条目数超过单批上限
	ErrMethodNotAllowed = "METHOD_NOT_ALLOWED"
	ErrNotFound         = "NOT_FOUND"
)

// ErrorResponse 是统一的结构化错误响应。
type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

// ErrorBody 描述一个错误。Code 为稳定的机器可读错误类型；Detail 给出可定位
// 问题的人类可读说明（例如哪个字段、允许取值是什么）。
type ErrorBody struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// ParamsDTO 是显式临时参数档的请求体表示。
// 数值字段同时接受 JSON 数字与字符串（含 "0x" 十六进制前缀），见 Uint64/Uint8。
type ParamsDTO struct {
	Width  *Uint8  `json:"width"`
	Poly   *Uint64 `json:"poly"`
	Init   *Uint64 `json:"init"`
	RefIn  *bool   `json:"ref_in"`
	RefOut *bool   `json:"ref_out"`
	XorOut *Uint64 `json:"xor_out"`
}

// ComputeRequest 是 POST /api/v1/checksums 的请求体。
// Profile 与 Params 二选一：给出具名档名，或给全五项约定临时构造一档。
type ComputeRequest struct {
	Profile string     `json:"profile,omitempty"`
	Params  *ParamsDTO `json:"params,omitempty"`
	Data    string     `json:"data"` // 必填；标准 base64，空串表示空载荷
	Engine  string     `json:"engine,omitempty"`
}

// ChecksumResponse 是编码接口的成功响应。
type ChecksumResponse struct {
	Profile string `json:"profile,omitempty"` // 具名档时回填档名
	Width   uint8  `json:"width"`
	Check   string `json:"check"` // 固定位宽、零填充的十六进制校验码
	Engine  string `json:"engine"`
}

// VerifyRequest 是 POST /api/v1/verify 的请求体。
type VerifyRequest struct {
	Profile  string     `json:"profile,omitempty"`
	Params   *ParamsDTO `json:"params,omitempty"`
	Data     string     `json:"data"`
	Checksum string     `json:"checksum"` // 与该档等宽的定长十六进制
	Engine   string     `json:"engine,omitempty"`
}

// VerifyResponse 是校验接口的成功响应。
type VerifyResponse struct {
	Profile  string `json:"profile,omitempty"`
	Width    uint8  `json:"width"`
	Valid    bool   `json:"valid"`
	Residual string `json:"residual"` // 重新除法后的余数；正确码字为全 0
	Engine   string `json:"engine"`
}

// ChunkRequest 是 POST /api/v1/chunks（分块流式核算）的请求体。
//
// 服务不保存任何分块进度：每次请求必须携带本分块在整段数据中的字节偏移
// offset，以及上一块响应返回的 state 令牌（首块省略，此时 offset 必须为 0）。
// 服务据此做纯函数式推进并返回新的 state 令牌。分块乱序或错位重传时，
// offset 与令牌内流位置不符，请求在计算前被拒绝（STATE_OFFSET_MISMATCH）；
// 用同一份 (state, offset, data) 重传则是幂等的，返回完全相同的结果。
type ChunkRequest struct {
	Profile string     `json:"profile,omitempty"`
	Params  *ParamsDTO `json:"params,omitempty"`
	Engine  string     `json:"engine,omitempty"`
	Offset  *Uint64    `json:"offset"`          // 必填：本分块首字节在整段数据中的偏移
	State   string     `json:"state,omitempty"` // 上一块响应的令牌；首块省略
	Data    string     `json:"data"`            // 本分块载荷；标准 base64，空串表示空分块
	Final   bool       `json:"final,omitempty"` // true 时收尾并额外返回整段校验码
}

// ChunkResponse 是分块推进的成功响应。
type ChunkResponse struct {
	Profile    string `json:"profile,omitempty"`
	Width      uint8  `json:"width"`
	Engine     string `json:"engine"`
	Offset     uint64 `json:"offset"`          // 本请求消费的流位置
	NextOffset uint64 `json:"next_offset"`     // 吃掉本分块后的流位置
	Bytes      int    `json:"bytes"`           // 本分块字节数
	State      string `json:"state"`           // 新的中间状态令牌（不透明，原样回传）
	Check      string `json:"check,omitempty"` // 仅 final=true：整段数据的定长十六进制校验码
}

// BatchRequest 是 POST /api/v1/checksums/batch（批量核算）的请求体。
// 每个条目与单次编码接口的请求体完全相同，共享同一套参数解析、
// 格式校验与错误码语义。
type BatchRequest struct {
	Items []ComputeRequest `json:"items"`
}

// BatchResult 是批量响应中单个条目的结果：要么 ok=true 并给出校验码，
// 要么 ok=false 并以与单次接口一致的结构化错误码说明失败原因。
type BatchResult struct {
	Index   int        `json:"index"` // 条目在请求 items 中的下标
	OK      bool       `json:"ok"`
	Profile string     `json:"profile,omitempty"`
	Width   uint8      `json:"width,omitempty"`
	Check   string     `json:"check,omitempty"`
	Engine  string     `json:"engine,omitempty"`
	Error   *ErrorBody `json:"error,omitempty"`
}

// BatchResponse 是批量核算的成功响应。只要请求信封合法，整体恒为 200，
// 各条目成败互不影响，由 results 逐项给出。
type BatchResponse struct {
	Results []BatchResult `json:"results"`
}

// HealthResponse 是监控采集用的运行状态。
type HealthResponse struct {
	Status        string    `json:"status"`
	Version       string    `json:"version"`
	Profiles      int       `json:"profiles"`
	UpSince       time.Time `json:"up_since"`
	UptimeSeconds int64     `json:"uptime_seconds"`
}

// Vector 是一个可直接核对的公开测试向量算例。
type Vector struct {
	Profile     string `json:"profile"`
	InputASCII  string `json:"input_ascii"`
	InputBase64 string `json:"input_base64"`
	ExpectedHex string `json:"expected_hex"`
	Width       uint8  `json:"width"`
	Source      string `json:"source"`
}
