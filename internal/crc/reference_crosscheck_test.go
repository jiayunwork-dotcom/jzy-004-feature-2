package crc

import (
	"math/rand"
	"testing"
)

// rocksoftReference 是独立于本包实现的 Rocksoft 规范参考算法，逐字照抄
// Williams 的定义式（先把输入按位反射进寄存器模型的处理顺序、最后再反射输出）。
// 它与 engine.go 不共享任何代码路径，用于交叉验证本包在 refIn/refOut 各种
// 组合下的结果。
func rocksoftReference(p Params, data []byte) uint64 {
	mask := Mask(p.Width)
	reg := p.Init & mask
	for _, b := range data {
		// 规范定义：每个输入字节先按位反射（若 refin），再按 MSB-first 喂入。
		if p.RefIn {
			b = byte(ReflectWidth(uint64(b), 8))
		}
		for i := 7; i >= 0; i-- {
			bit := uint64((b >> uint(i)) & 1)
			feedback := ((reg >> (p.Width - 1)) & 1) ^ bit
			reg = (reg << 1) & mask
			if feedback != 0 {
				reg ^= p.Poly
			}
		}
	}
	// 规范定义：输出对最终寄存器整体按 width 位反射（若 refout）。
	if p.RefOut {
		reg = ReflectWidth(reg, p.Width)
	}
	return (reg ^ p.XorOut) & mask
}

// 用规范参考实现交叉核对：内置档 + 随机档（含全部四种 refin/refout 组合
// 与非字节位宽），两路引擎都必须与参考值一致。
func TestCrossCheckRocksoftReference(t *testing.T) {
	// 内置标准档。
	for _, prof := range ListProfiles() {
		for _, eng := range []Engine{EngineBitwise, EngineTable} {
			got := Compute(prof.Params, StandardVector, eng)
			want := rocksoftReference(prof.Params, StandardVector)
			if got != want || got != prof.Check {
				t.Fatalf("%s [%s] got %#x reference %#x catalog %#x",
					prof.Name, eng, got, want, prof.Check)
			}
		}
	}

	// 随机档。
	rng := rand.New(rand.NewSource(20240918))
	for iter := 0; iter < 300; iter++ {
		w := uint8(8 + rng.Intn(57)) // 覆盖 12、13 等非字节宽度
		mask := Mask(w)
		p := Params{
			Width:  w,
			Poly:   (rng.Uint64() | 1) & mask,
			Init:   rng.Uint64() & mask,
			XorOut: rng.Uint64() & mask,
			RefIn:  rng.Intn(2) == 0,
			RefOut: rng.Intn(2) == 0,
		}
		data := make([]byte, rng.Intn(50))
		rng.Read(data)
		want := rocksoftReference(p, data)
		if got := Compute(p, data, EngineBitwise); got != want {
			t.Fatalf("iter %d %+v bitwise %#x != reference %#x", iter, p, got, want)
		}
		if got := Compute(p, data, EngineTable); got != want {
			t.Fatalf("iter %d %+v table %#x != reference %#x", iter, p, got, want)
		}
		// 参考实现产生的码必须被 Verify 接受。
		if _, ok := Verify(p, data, want, EngineBitwise); !ok {
			t.Fatalf("iter %d %+v reference check rejected", iter, p)
		}
	}
}
