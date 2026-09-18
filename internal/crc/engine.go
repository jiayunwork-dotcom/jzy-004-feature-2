package crc

import "sync"

// Engine 选择除法路径。两条路径必须对同一输入给出完全相同的余数。
type Engine string

const (
	EngineBitwise Engine = "bitwise" // 按位逐比特长除法
	EngineTable   Engine = "table"   // 按字节查表（256 项表）
)

// ParseEngine 解析调用方指定的除法路径，未指定时默认 table。
func ParseEngine(s string) (engine Engine, valid bool) {
	switch s {
	case "", "table":
		return EngineTable, true
	case "bitwise":
		return EngineBitwise, true
	default:
		return "", false
	}
}

// cacheKey 唯一标识一份“仅依赖 width/poly/refIn”的推导结果。
type cacheKey struct {
	width uint8
	poly  uint64
	refIn bool
}

// initKey 标识反射后的初值（仅依赖 width 与 init）。
type initKey struct {
	width uint8
	init  uint64
}

var (
	rpolyCache sync.Map // polyKey  -> uint64，按 width 位反转后的多项式
	tableCache sync.Map // cacheKey -> *[256]uint64，字节查表
	rinitCache sync.Map // initKey  -> uint64，按 width 位反转后的初值
)

// startRegister 返回某参数档除法寄存器的起始值。
//
// 反射（refIn=true）路径相对规范 Rocksoft 模型，多项式与初值都要按 width 位
// 反转后再进入 LSB-first 除法；末级仅在 refOut 与 refIn 不一致时反转
// （见 finish）。对字节宽度且初值为全 0/全 1 的常见标准档，反转初值后不变，
// 因此本处理与既有标准反射实现（如 zlib crc32、CRC-16/MODBUS）结果一致；
// 但对非字节宽度或任意初值的显式临时档，反转初值是保证与规范模型逐位一致的
// 必要步骤。
func startRegister(p Params) uint64 {
	if p.RefIn {
		k := initKey{p.Width, p.Init}
		if v, ok := rinitCache.Load(k); ok {
			return v.(uint64)
		}
		v := ReflectWidth(p.Init, p.Width)
		actual, _ := rinitCache.LoadOrStore(k, v)
		return actual.(uint64)
	}
	return p.Init
}

// polyKey 标识按位反转后的多项式（仅依赖 width 与 poly）。
type polyKey struct {
	width uint8
	poly  uint64
}

// reflectedPoly 返回 poly 在 width 位下的按位反转值（惰性缓存）。
func reflectedPoly(p Params) uint64 {
	k := polyKey{p.Width, p.Poly}
	if v, ok := rpolyCache.Load(k); ok {
		return v.(uint64)
	}
	v := ReflectWidth(p.Poly, p.Width)
	actual, _ := rpolyCache.LoadOrStore(k, v)
	return actual.(uint64)
}

// clockMSB 是非反转路径上单个比特的 CRC 时钟（MSB-first）：数据位在
// 反馈点进入——与移出寄存器的最高位异或后决定是否减去除式。
// 这与“字节先异或到寄存器高端、再连续 8 次移位”的规范字节算法严格等价，
// 是 Rocksoft 规范模型的逐比特版本。
func clockMSB(p Params, reg uint64, dataBit uint64) uint64 {
	mask := Mask(p.Width)
	feedback := ((reg >> (p.Width - 1)) & 1) ^ (dataBit & 1)
	reg = (reg << 1) & mask
	if feedback != 0 {
		reg ^= p.Poly
	}
	return reg
}

// clockReflected 是输入反转（refIn）路径上单个比特的 CRC 时钟（LSB-first）：
// 数据位在最低位反馈点进入，寄存器右移，移出位为 1 时异或“按 width 位反转
// 后的多项式”。它与“先逐字节反转输入、再走 MSB 长除法”严格等价，
// 是 refIn/refOut 唯一的实现解释。
func clockReflected(p Params, reg uint64, dataBit uint64) uint64 {
	feedback := (reg & 1) ^ (dataBit & 1)
	reg >>= 1
	if feedback != 0 {
		reg ^= reflectedPoly(p)
	}
	return reg
}

// rawRemainderBitwise 以按位逐比特方式对 data 做长除法，返回最终寄存器
// （尚未做输出反转与最终异或）。reg 为起始寄存器（编码时传 p.Init）。
func rawRemainderBitwise(p Params, data []byte, reg uint64) uint64 {
	if p.RefIn {
		for _, b := range data {
			for i := uint(0); i < 8; i++ {
				reg = clockReflected(p, reg, uint64((b>>i)&1)) // 逐字节 LSB-first
			}
		}
		return reg
	}
	for _, b := range data {
		for i := uint(0); i < 8; i++ {
			reg = clockMSB(p, reg, uint64((b>>(7-i))&1)) // MSB-first
		}
	}
	return reg
}

// lookupTable 惰性构建并缓存某参数档（仅与 width/poly/refIn 有关）的 256
// 项查表，对应一个字节 8 次时钟步进的净效果。
func lookupTable(p Params) *[256]uint64 {
	k := cacheKey{p.Width, p.Poly, p.RefIn}
	if v, ok := tableCache.Load(k); ok {
		return v.(*[256]uint64)
	}
	t := buildTable(p)
	actual, _ := tableCache.LoadOrStore(k, &t)
	return actual.(*[256]uint64)
}

func buildTable(p Params) [256]uint64 {
	var t [256]uint64
	if p.RefIn {
		rp := ReflectWidth(p.Poly, p.Width)
		for i := 0; i < 256; i++ {
			c := uint64(i)
			for j := 0; j < 8; j++ {
				feedback := c & 1
				c >>= 1
				if feedback != 0 {
					c ^= rp
				}
			}
			t[i] = c
		}
		return t
	}
	mask := Mask(p.Width)
	top := uint64(1) << (p.Width - 1)
	for i := 0; i < 256; i++ {
		c := uint64(i) << (p.Width - 8)
		for j := 0; j < 8; j++ {
			feedback := c & top
			c = (c << 1) & mask
			if feedback != 0 {
				c ^= p.Poly
			}
		}
		t[i] = c
	}
	return t
}

// rawRemainderTable 以按字节查表方式做除法。其每一步等价于 8 次比特时钟，
// 因此必须与 rawRemainderBitwise 逐位相等。
func rawRemainderTable(p Params, data []byte, reg uint64) uint64 {
	t := lookupTable(p)
	mask := Mask(p.Width)
	if p.RefIn {
		for _, b := range data {
			idx := byte(reg) ^ b
			reg = (reg >> 8) ^ t[idx]
		}
		return reg
	}
	for _, b := range data {
		idx := byte(reg>>(p.Width-8)) ^ b
		reg = ((reg << 8) & mask) ^ t[idx]
	}
	return reg
}

// rawRemainder 按指定路径计算“未做末级反射与最终异或”的寄存器余数。
func rawRemainder(p Params, data []byte, engine Engine) uint64 {
	if engine == EngineBitwise {
		return rawRemainderBitwise(p, data, startRegister(p))
	}
	return rawRemainderTable(p, data, startRegister(p))
}

// finish 套用该档的输出约定，得到对外可见的校验码。
//
// 反转语义在全包内只解释一次：refIn=true 时寄存器按 LSB-first 的反射除法
// 维护，其寄存器值天然已处于“输出反射后”的方向（这正是 zlib crc32 等
// 反射实现不再做末级反转的原因）。因此末级反射仅当 refOut 与 refIn
// 不一致时才需要：
//
//	refIn=false refOut=false：不反射
//	refIn=false refOut=true ：对 MSB 余数反射
//	refIn=true  refOut=true ：不反射（已在反射方向上）
//	refIn=true  refOut=false：对反射余数反射回规范方向
func finish(p Params, reg uint64) uint64 {
	if p.RefOut != p.RefIn {
		reg = ReflectWidth(reg, p.Width)
	}
	return (reg ^ p.XorOut) & Mask(p.Width)
}

// Compute 按参数档 p 计算 data 的 CRC 校验码。
// p 必须已通过 Validate；engine 选择按位或查表除法路径。
func Compute(p Params, data []byte, engine Engine) uint64 {
	return finish(p, rawRemainder(p, data, engine))
}

// appendRemainderBits 在已处理完 data 的寄存器 reg 之后，继续移入校验字段
// 的 w 个比特并返回最终寄存器。比特顺序与 refIn 的数据顺序保持一致：
// refIn=false 时 MSB-first；refIn=true 时 LSB-first。
// 校验字段只有 width 位（最多 64 比特），直接走逐比特时钟即可，它与查表
// 路径在数据段上模拟的是同一条递推，因此不影响两路同余。
func appendRemainderBits(p Params, reg uint64, rawA uint64) uint64 {
	if p.RefIn {
		for i := uint8(0); i < p.Width; i++ {
			reg = clockReflected(p, reg, (rawA>>i)&1)
		}
		return reg
	}
	for i := uint8(0); i < p.Width; i++ {
		reg = clockMSB(p, reg, (rawA>>(p.Width-1-i))&1)
	}
	return reg
}

// Verify 对“数据 + 校验码”重新走一遍除法：先恢复出除法寄存器空间里的
// 原始余数 A（撤销最终异或与输出反转），把 A 作为校验字段按该档位序追加
// 到数据之后继续做长除法。正确码字的最终余数恒为零；任何数据或校验码比特
// 被翻转，余数都不为零。
//
// 返回最终余数（固定位宽内的值，零即通过）与是否通过。
func Verify(p Params, data []byte, check uint64, engine Engine) (residual uint64, ok bool) {
	rawA := check ^ p.XorOut // 撤销最终异或
	if p.RefOut != p.RefIn {
		rawA = ReflectWidth(rawA, p.Width) // 撤销末级反射（与 finish 对称）
	}
	reg := rawRemainder(p, data, engine)
	reg = appendRemainderBits(p, reg, rawA)
	return reg, reg == 0
}
