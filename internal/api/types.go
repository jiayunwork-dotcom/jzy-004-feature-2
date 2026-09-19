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
	ErrStateInvalid     = "STATE_INVALID"         // 流式状态令牌无法解析或未通过完整性校验
	ErrStateMismatch    = "STATE_MISMATCH"        // 分块偏移/参数档与已认证的流式状态冲突
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

// StreamRequest 是 POST /api/v1/stream 的请求体：在流式核算中推进一个分块。
//
// 首个分块不带 state，必须给出 profile 或 params（与单次接口同一套解析），
// offset 只能为 0（缺省即 0）。后续分块回传上一响应的 state；此时
// profile/params 可省略（取令牌内已认证的参数档），若给出则必须与令牌内
// 参数档一致，否则拒绝。offset 必须等于令牌中已认证的下一偏移，乱序或重复
// 分块因此被拒绝。final=true 表示这是最后一块，响应给出最终校验码而不再
// 签发新状态。
type StreamRequest struct {
	Profile string     `json:"profile,omitempty"`
	Params  *ParamsDTO `json:"params,omitempty"`
	Engine  string     `json:"engine,omitempty"`
	State   string     `json:"state,omitempty"`  // 上一响应签发的状态令牌；首块缺省
	Offset  *uint64    `json:"offset,omitempty"` // 本分块在整段数据中的字节偏移
	Final   bool       `json:"final,omitempty"`  // 是否为最后一块
	Data    string     `json:"data"`             // 本分块载荷；标准 base64，空串为空分块
}

// StreamResponse 是分块推进的响应。final=false 时签发下一状态令牌；
// final=true 时给出与单次接口逐位一致的最终校验码。
type StreamResponse struct {
	Profile    string `json:"profile,omitempty"`
	Width      uint8  `json:"width"`
	Engine     string `json:"engine"`
	Offset     uint64 `json:"offset"`      // 本次接收分块的起始偏移
	Length     int    `json:"length"`      // 本次接收分块的字节数
	NextOffset uint64 `json:"next_offset"` // 下一块必须携带的偏移
	Final      bool   `json:"final"`
	State      string `json:"state,omitempty"` // 仅 final=false：供下一块回传的令牌
	Check      string `json:"check,omitempty"` // 仅 final=true：整段数据的校验码
}

// BatchRequest 是 POST /api/v1/checksums/batch 的请求体。
// Engine 为整批默认除法路径，可被单条的 engine 覆盖。
type BatchRequest struct {
	Engine string             `json:"engine,omitempty"`
	Items  []BatchItemRequest `json:"items"` // 必填，至少为数组；上限 maxBatchItems
}

// BatchItemRequest 是批量核算中的一条 (参数档或临时档, 载荷) 组合，
// 字段语义与 ComputeRequest 完全一致。
type BatchItemRequest struct {
	Profile string     `json:"profile,omitempty"`
	Params  *ParamsDTO `json:"params,omitempty"`
	Data    string     `json:"data"`
	Engine  string     `json:"engine,omitempty"`
}

// BatchItemResult 是批量中一条的结果：成功时给出与单次接口完全相同的
// 字段；失败时 error 定位原因（与单次接口同一套错误码），不影响其它条。
type BatchItemResult struct {
	Index   int        `json:"index"` // 对应请求 items 的下标
	OK      bool       `json:"ok"`
	Profile string     `json:"profile,omitempty"`
	Width   uint8      `json:"width,omitempty"`
	Check   string     `json:"check,omitempty"`
	Engine  string     `json:"engine,omitempty"`
	Error   *ErrorBody `json:"error,omitempty"`
}

// BatchResponse 是批量核算的响应：每条请求各有一个结果，顺序与下标对应。
// 只要请求本身合法，整体恒返回 200；单条成败由各自结果的 ok 字段判定。
type BatchResponse struct {
	Results []BatchItemResult `json:"results"`
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
