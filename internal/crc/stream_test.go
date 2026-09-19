package crc

import (
	"math/rand"
	"testing"
)

// chainCompute 按分块流式方式折叠出整段数据的校验码：
// 起始寄存器 → 逐块推进 → 末级一次完成。每块可用不同引擎。
func chainCompute(p Params, chunks [][]byte, engines []Engine) uint64 {
	reg := InitRegister(p)
	for i, c := range chunks {
		reg = AdvanceRegister(p, reg, c, engines[i%len(engines)])
	}
	return FinalizeRegister(p, reg)
}

// splitChunks 按给定块长切分（允许 0 长度块；最后一个正长度块之后的
// 空块也保留，模拟「末块之后还有空推进」）。
func splitChunks(data []byte, sizes []int) [][]byte {
	chunks := make([][]byte, 0, len(sizes))
	off := 0
	for _, n := range sizes {
		if n > len(data)-off {
			n = len(data) - off
		}
		chunks = append(chunks, data[off:off+n])
		off += n
	}
	if off < len(data) {
		chunks = append(chunks, data[off:])
	}
	return chunks
}

// 分块合并与整体一致：全部内置档 × 两种引擎 × 多种切分方式
// （含空块、单字节块、末块长度不同、退化单块），链式结果必须逐位等于
// 一次性 Compute。
func TestChainMatchesComputeBuiltinProfiles(t *testing.T) {
	rng := rand.New(rand.NewSource(20260919))
	payloads := [][]byte{
		nil,
		{},
		[]byte("a"),
		[]byte("123456789"),
	}
	big := make([]byte, 1027) // 非对齐长度，覆盖任意末块
	rng.Read(big)
	payloads = append(payloads, big)

	chunkings := [][]int{
		{1 << 30},                   // 退化：一整块
		{1},                         // 逐字节由循环补足？否——{1} 只切首字节，其余并入末块
		{0, 0, 0},                   // 全空块 + 剩余整体
		{1, 1, 1, 1, 1, 1, 1, 1, 1}, // 单字节块
		{7, 0, 64, 3, 255, 0, 100},  // 混合：空块穿插、末块长度不同
		{0},                         // 首块为空
	}
	for _, prof := range ListProfiles() {
		for _, data := range payloads {
			for _, sizes := range chunkings {
				chunks := splitChunks(data, sizes)
				for _, eng := range []Engine{EngineBitwise, EngineTable} {
					got := chainCompute(prof.Params, chunks, []Engine{eng})
					want := Compute(prof.Params, data, eng)
					if got != want {
						t.Fatalf("%s len=%d sizes=%v %s: chained %#x != one-shot %#x",
							prof.Name, len(data), sizes, eng, got, want)
					}
				}
			}
		}
	}
}

// 随机临时档（含非字节宽度、refIn!=refOut 混合档、xor_out 非零）× 随机载荷
// × 随机切分（含空块）× 逐块混用引擎：链式结果必须等于一次性 Compute，
// 且与独立 Rocksoft 参考实现一致。
func TestChainMatchesComputeRandomProfiles(t *testing.T) {
	rng := rand.New(rand.NewSource(987654321))
	engines := []Engine{EngineBitwise, EngineTable}
	for iter := 0; iter < 400; iter++ {
		w := uint8(8 + rng.Intn(57))
		mask := Mask(w)
		p := Params{
			Width:  w,
			Poly:   (rng.Uint64() | 1) & mask,
			Init:   rng.Uint64() & mask,
			XorOut: rng.Uint64() & mask,
			RefIn:  rng.Intn(2) == 0,
			RefOut: rng.Intn(2) == 0,
		}
		data := make([]byte, rng.Intn(300))
		rng.Read(data)

		// 随机切分：块长 0..17，保证空块与单字节块高频出现。
		var sizes []int
		for remaining := len(data); remaining > 0; {
			n := rng.Intn(18)
			sizes = append(sizes, n)
			remaining -= n
		}
		// 末尾再补几个空块（末块之后的空推进必须是恒等）。
		for i := 0; i < rng.Intn(3); i++ {
			sizes = append(sizes, 0)
		}
		chunks := splitChunks(data, sizes)

		// 逐块随机选引擎：两条除法路径同余，混用不得改变结果。
		mixed := make([]Engine, len(chunks))
		for i := range mixed {
			mixed[i] = engines[rng.Intn(2)]
		}
		want := Compute(p, data, EngineTable)
		if got := chainCompute(p, chunks, mixed); got != want {
			t.Fatalf("iter %d %+v len=%d: chained %#x != one-shot %#x",
				iter, p, len(data), got, want)
		}
		if ref := rocksoftReference(p, data); want != ref {
			t.Fatalf("iter %d %+v: one-shot %#x != rocksoft reference %#x",
				iter, p, want, ref)
		}
	}
}

// 前缀性质：任意前缀推进完成后立即 FinalizeRegister，必须等于对该前缀
// 单独 Compute——证明 init/反射/xor_out 没有在分块边界提前或重复作用。
func TestChainPrefixProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(31337))
	for iter := 0; iter < 100; iter++ {
		w := uint8(8 + rng.Intn(57))
		mask := Mask(w)
		p := Params{
			Width:  w,
			Poly:   (rng.Uint64() | 1) & mask,
			Init:   rng.Uint64() & mask,
			XorOut: rng.Uint64() & mask,
			RefIn:  rng.Intn(2) == 0,
			RefOut: rng.Intn(2) == 0,
		}
		data := make([]byte, 1+rng.Intn(200))
		rng.Read(data)
		reg := InitRegister(p)
		for i := range data {
			reg = AdvanceRegister(p, reg, data[i:i+1], EngineTable)
			if got, want := FinalizeRegister(p, reg), Compute(p, data[:i+1], EngineTable); got != want {
				t.Fatalf("iter %d prefix %d: %#x != %#x", iter, i+1, got, want)
			}
		}
	}
}

// 空分块是恒等推进；起始寄存器与末级完成都不会被空推进影响。
func TestChainEmptyChunkIdentity(t *testing.T) {
	for _, prof := range ListProfiles() {
		reg := InitRegister(prof.Params)
		for _, eng := range []Engine{EngineBitwise, EngineTable} {
			if got := AdvanceRegister(prof.Params, reg, nil, eng); got != reg {
				t.Fatalf("%s %s: empty chunk changed register %#x -> %#x",
					prof.Name, eng, reg, got)
			}
		}
		// 整段为空（只有起始与完成，没有任何分块）必须等于空载荷单次结果。
		if got, want := FinalizeRegister(prof.Params, reg), Compute(prof.Params, nil, EngineTable); got != want {
			t.Fatalf("%s: zero-chunk chain %#x != empty one-shot %#x", prof.Name, got, want)
		}
	}
}

// 分块推进的中间寄存器被翻转任意比特后，最终校验码必须改变
// （分块链路不会「吸收」篡改）。
func TestChainStateBitFlipChangesResult(t *testing.T) {
	p, _ := GetProfile("CRC-16/CCITT-FALSE")
	data := []byte("stream state tamper probe")
	reg := InitRegister(p.Params)
	reg = AdvanceRegister(p.Params, reg, data[:10], EngineTable)
	final := FinalizeRegister(p.Params, AdvanceRegister(p.Params, reg, data[10:], EngineTable))
	for bit := uint8(0); bit < p.Params.Width; bit++ {
		tampered := reg ^ (uint64(1) << bit)
		got := FinalizeRegister(p.Params, AdvanceRegister(p.Params, tampered, data[10:], EngineTable))
		if got == final {
			t.Fatalf("flipping state bit %d left final checksum unchanged", bit)
		}
	}
}
