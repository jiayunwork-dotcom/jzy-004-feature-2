package api

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
)

var (
	uint64Type = reflect.TypeOf(uint64(0))
	uint8Type  = reflect.TypeOf(uint8(0))
)

// Uint64 用于请求体中的 width/poly/init/xor_out 等字段：CRC 约定惯例上以
// 十六进制书写（如 poly=0x1021），因此它同时接受 JSON 数字与字符串：
//
//	16         → 十进制 16
//	"16"       → 十进制 16
//	"0x1021"   → 十六进制
//	"1021"     → 十进制（无 0x 前缀时按十进制解析，避免歧义）
type Uint64 uint64

// UnmarshalJSON 实现 encoding/json 的兼容解析。
func (u *Uint64) UnmarshalJSON(data []byte) error {
	s := strings.TrimSpace(string(data))
	if s == "" || s == "null" {
		return nil
	}
	if strings.HasPrefix(s, "\"") {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}
		str = strings.TrimSpace(str)
		base := 10
		if strings.HasPrefix(str, "0x") || strings.HasPrefix(str, "0X") {
			str = str[2:]
			base = 16
		}
		v, err := strconv.ParseUint(str, base, 64)
		if err != nil {
			return &json.UnmarshalTypeError{Value: "number string " + string(data), Type: uint64Type}
		}
		*u = Uint64(v)
		return nil
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return err
	}
	*u = Uint64(v)
	return nil
}

// Uint8 同理，用于 width 字段。
type Uint8 uint8

// UnmarshalJSON 兼容数字与字符串（含 0x 前缀）。
func (u *Uint8) UnmarshalJSON(data []byte) error {
	var v Uint64
	if err := v.UnmarshalJSON(data); err != nil {
		return err
	}
	if v > 255 {
		return &json.UnmarshalTypeError{Value: string(data), Type: uint8Type}
	}
	*u = Uint8(v)
	return nil
}
