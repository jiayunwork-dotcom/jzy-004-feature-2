package crc

// 分块流式核算：把「整段数据一次性除法」拆成若干有序分块逐步推进，
// 合并结果与一次性计算逐位相同。
//
// 数学依据：rawRemainder* 对寄存器是纯递推（对字节/比特序列的 fold），
// 因此对任意切分 data = c1 ++ c2 ++ ... ++ cn 恒有
//
//	Compute(p, data)
//	  == FinalizeRegister(p,
//	       AdvanceRegister(p, ... AdvanceRegister(p, InitRegister(p), c1) ..., cn))
//
// init 只在 InitRegister 进入寄存器一次，输出反转与 xor_out 只在
// FinalizeRegister 作用一次；分块边界本身不引入任何额外作用。该性质对任意
// 合法参数档成立——包括 refIn != refOut 的混合档、非字节整数倍宽度、
// xor_out 非零的临时档——因为这三者都只出现在首尾两处，从不参与递推。

// InitRegister 返回流式核算的起始寄存器（init 唯一生效处）。
// p 必须已通过 Validate。
func InitRegister(p Params) uint64 { return startRegister(p) }

// AdvanceRegister 在中间寄存器 state 上继续吃掉一个分块，返回新的中间寄存器。
// 空分块是恒等推进（state 原样返回）。engine 选择除法路径；两条路径同余，
// 同一条流的不同分块可以混用引擎而结果不变。
func AdvanceRegister(p Params, state uint64, chunk []byte, engine Engine) uint64 {
	if engine == EngineBitwise {
		return rawRemainderBitwise(p, chunk, state)
	}
	return rawRemainderTable(p, chunk, state)
}

// FinalizeRegister 在最后一个分块推进完毕后套用该档的输出约定
// （末级反射 + xor_out，各仅一次），得到与 Compute 逐位相同的校验码。
func FinalizeRegister(p Params, state uint64) uint64 { return finish(p, state) }
