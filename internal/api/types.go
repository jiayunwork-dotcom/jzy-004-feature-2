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
