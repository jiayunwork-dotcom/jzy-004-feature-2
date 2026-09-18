// Package crc 实现无状态的循环冗余校验（CRC）核算。
//
// 一个参数档（Params）完整描述一种 CRC 算法的全部约定，字段语义与
// CRC RevEng / zlib catalog（Rocksoft 模型）一致：
//
//	width  CRC 位宽（寄存器位数）
//	poly   多项式（MSB-first 规范表示，隐去最高次 x^width 项，1..2^width-1）
//	init   寄存器初值
//	refIn  输入是否按位反转（逐字节 LSB-first 处理）
//	refOut 输出是否按位反转（对最终寄存器值按 width 位反转）
//	xorOut 最终异或值
//
// 反转语义只在本包内解释一次：bitwise 与 table 两条除法路径共享同一套
// 输入反转/输出反转逻辑，保证编码与校验两侧严格一致。
package crc

import "errors"

// WidthMin / WidthMax 限定本服务支持的 CRC 位宽。
// 下限取 8 是为了让按字节查表路径与按位路径在同一宽度域内可比；
// 上限 64 对应 uint64 寄存器。
const (
	WidthMin = 8
	WidthMax = 64
)

// Params 是一个完整的 CRC 参数档。
type Params struct {
	Width  uint8  `json:"width"`
	Poly   uint64 `json:"poly"`
	Init   uint64 `json:"init"`
	RefIn  bool   `json:"ref_in"`
	RefOut bool   `json:"ref_out"`
	XorOut uint64 `json:"xor_out"`
}

// 显式临时参数档的校验错误。
var (
	ErrWidthOutOfRange = errors.New("width must be between 8 and 64")
	ErrPolyOutOfRange  = errors.New("poly must be between 1 and 2^width-1")
	ErrPolyEven        = errors.New("poly must have its constant term x^0 set (lowest bit 1); " +
		"even polynomials are not valid CRC divisors")
	ErrInitOutOfRange = errors.New("init must not exceed 2^width-1")
	ErrXorOutOfRange  = errors.New("xor_out must not exceed 2^width-1")
)

// Validate 在开始任何计算之前校验参数档的合法性，非法即拒绝。
func (p Params) Validate() error {
	if p.Width < WidthMin || p.Width > WidthMax {
		return ErrWidthOutOfRange
	}
	m := Mask(p.Width)
	if p.Poly < 1 || p.Poly > m {
		return ErrPolyOutOfRange
	}
	// 生成多项式必须含常数项（x^0 系数为 1），否则除式含因子 x，
	// 连单比特错误检测能力都不成立。Rocksoft catalog 中所有标准档均满足。
	if p.Poly&1 == 0 {
		return ErrPolyEven
	}
	if p.Init > m {
		return ErrInitOutOfRange
	}
	if p.XorOut > m {
		return ErrXorOutOfRange
	}
	return nil
}

// Mask 返回 width 位全 1 掩码；width=64 时为 math.MaxUint64。
func Mask(width uint8) uint64 {
	if width >= 64 {
		return ^uint64(0)
	}
	return uint64(1)<<width - 1
}

// ReflectWidth 将 value 的低 width 位按位反转，高位丢弃。
// 输入逐字节反转（refIn）与输出整体反转（refOut）都复用这一个函数，
// 使“反转”语义在全包内只有一种解释。
func ReflectWidth(value uint64, width uint8) uint64 {
	var r uint64
	for i := uint8(0); i < width; i++ {
		if (value>>i)&1 == 1 {
			r |= uint64(1) << (width - 1 - i)
		}
	}
	return r
}

// reflectByteTable 由 ReflectWidth 预生成 256 个字节的按位反转表
// （refIn 的逐字节处理），使“反转”语义在全包内只有一种解释。
var reflectByteTable = func() [256]byte {
	var t [256]byte
	for i := 0; i < 256; i++ {
		t[i] = byte(ReflectWidth(uint64(i), 8))
	}
	return t
}()

// ReflectedByte 返回 b 的按位反转结果。
func ReflectedByte(b byte) byte { return reflectByteTable[b] }
