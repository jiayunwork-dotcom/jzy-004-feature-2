package crc

// 本文件把一次性除法拆成「首块开始 → 逐块推进 → 末块收尾」三个纯函数，
// 支撑无状态的分块流式核算：服务不保存任何分块进度，中间寄存器由调用方
// 在请求间回传。
//
// 数学正确性：rawRemainderBitwise / rawRemainderTable 都是从任意起始寄存器
// 出发的同一条递推（查表路径每步严格等于 8 次比特时钟），因此对任意字节
// 序列 c1..cn 与任意切分方式都有
//
//	Finalize(p, Advance(p, ...Advance(p, Begin(p), c1)..., cn))
//		== Compute(p, c1|...|cn, engine)
//
// 分块边界只是字节边界，递推与位置无关，故对任意合法参数档成立——包括
// refIn 与 refOut 不一致的混合档、非字节整数倍宽度档、xor_out 非零档。
// init 只在 Begin 生效一次；输入反转是逐字节的固有处理而非边界效应；
// 输出反转与 xor_out 只在 Finalize 生效一次，绝不在分块边界重复作用。

// Begin 返回一段新流式核算的起始寄存器（init 仅在此处生效一次）。
// p 必须已通过 Validate。
func Begin(p Params) uint64 { return startRegister(p) }

// Advance 在中间寄存器 reg 上继续吃掉一个分块 data，返回新的中间寄存器。
// 空分块是恒等推进（返回 reg 本身）。engine 两条路径严格同余，同一段流的
// 不同分块可以混用引擎。
func Advance(p Params, reg uint64, data []byte, engine Engine) uint64 {
	if engine == EngineBitwise {
		return rawRemainderBitwise(p, data, reg)
	}
	return rawRemainderTable(p, data, reg)
}

// Finalize 对最终中间寄存器套用该档的输出约定（末级反射 + xor_out，
// 仅在此处生效一次），得到与 Compute 逐位一致的对外校验码。
func Finalize(p Params, reg uint64) uint64 { return finish(p, reg) }
