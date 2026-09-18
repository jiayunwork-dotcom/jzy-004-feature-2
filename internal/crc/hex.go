package crc

import (
	"errors"
	"fmt"
)

// 校验码十六进制表示的解析错误。
var (
	ErrHexInvalid  = errors.New("checksum is not valid hexadecimal")
	ErrHexTooLong  = errors.New("checksum has more hex digits than the profile width")
	ErrHexTooShort = errors.New("checksum must use exactly ceil(width/4) hex digits")
)

// HexDigits 返回 width 位宽对应的固定十六进制位数 ceil(width/4)。
func HexDigits(width uint8) int {
	return (int(width) + 3) / 4
}

// FormatHex 将校验码格式化为该位宽下定长、零填充的小写十六进制字符串。
func FormatHex(value uint64, width uint8) string {
	return fmt.Sprintf("%0*x", HexDigits(width), value)
}

// ParseHex 解析定长十六进制校验码，要求恰好 ceil(width/4) 位且数值不超过
// width 位掩码（例如 width=12 时十六进制最高位只允许 0/1）。
func ParseHex(s string, width uint8) (uint64, error) {
	digits := HexDigits(width)
	if len(s) != digits {
		// 给出更具体的错误类型，便于调用方区分。
		if len(s) > digits {
			return 0, ErrHexTooLong
		}
		return 0, ErrHexTooShort
	}
	var v uint64
	for _, r := range s {
		var d uint64
		switch {
		case r >= '0' && r <= '9':
			d = uint64(r - '0')
		case r >= 'a' && r <= 'f':
			d = uint64(r-'a') + 10
		case r >= 'A' && r <= 'F':
			d = uint64(r-'A') + 10
		default:
			return 0, ErrHexInvalid
		}
		v = v<<4 | d
	}
	if v > Mask(width) {
		return 0, ErrHexTooLong
	}
	return v, nil
}
