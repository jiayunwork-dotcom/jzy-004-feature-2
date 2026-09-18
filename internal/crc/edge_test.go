package crc

import (
	"math/rand"
	"testing"
)

// 专门压测此前暴露问题的角落：refIn=true 且非字节宽度 + 任意非零 init，
// refIn/refOut 全组合，穷举单比特翻转。
func TestReflectedNonByteWidthEdge(t *testing.T) {
	rng := rand.New(rand.NewSource(555))
	widths := []uint8{9, 11, 12, 13, 15, 17, 23, 29, 31, 33, 47, 63}
	for _, w := range widths {
		mask := Mask(w)
		// 刻意选一个位反转后会变化的 init（避免全 0/全 1 的平凡情形）。
		initv := (uint64(0x9e3779b97f4a7c15) >> (64 - w)) & mask
		if initv == ReflectWidth(initv, w) {
			initv ^= 1 // 确保反转后不同
		}
		for _, refOut := range []bool{false, true} {
			p := Params{
				Width: w, Poly: (rng.Uint64() | 1) & mask,
				Init: initv, XorOut: (rng.Uint64()) & mask,
				RefIn: true, RefOut: refOut,
			}
			data := []byte("non-byte-width reflected edge case")
			cb := Compute(p, data, EngineBitwise)
			ct := Compute(p, data, EngineTable)
			if cb != ct {
				t.Fatalf("w=%d refout=%v engine mismatch %#x vs %#x", w, refOut, cb, ct)
			}
			if cb != rocksoftReference(p, data) {
				t.Fatalf("w=%d refout=%v mismatch canonical", w, refOut)
			}
			if res, ok := Verify(p, data, cb, EngineTable); !ok || res != 0 {
				t.Fatalf("w=%d refout=%v roundtrip fail res=%#x", w, refOut, res)
			}
			for bit := uint8(0); bit < w; bit++ {
				if _, ok := Verify(p, data, cb^(1<<bit), EngineTable); ok {
					t.Fatalf("w=%d refout=%v check bit %d flip accepted", w, refOut, bit)
				}
			}
			for bit := 0; bit < len(data)*8; bit++ {
				d2 := append([]byte(nil), data...)
				d2[bit/8] ^= 1 << (bit % 8)
				if _, ok := Verify(p, d2, cb, EngineBitwise); ok {
					t.Fatalf("w=%d refout=%v data bit %d flip accepted", w, refOut, bit)
				}
			}
		}
	}
}
