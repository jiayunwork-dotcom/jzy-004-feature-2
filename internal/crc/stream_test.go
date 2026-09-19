package crc

import (
	"math/rand"
	"testing"
)

// 随机合法参数档（含混合反转、非字节宽度、xor_out 非零）。
func randomStreamParams(rng *rand.Rand) Params {
	w := uint8(8 + rng.Intn(57))
	mask := Mask(w)
	return Params{
		Width:  w,
		Poly:   (rng.Uint64() | 1) & mask,
		Init:   rng.Uint64() & mask,
		RefIn:  rng.Intn(2) == 0,
		RefOut: rng.Intn(2) == 0,
		XorOut: rng.Uint64() & mask,
	}
}

// 把 data 随机切分成若干块，刻意掺入空块与单字节块，末块长度允许不同。
func randomSplit(rng *rand.Rand, data []byte) [][]byte {
	var chunks [][]byte
	for pos := 0; pos < len(data); {
		var n int
		switch rng.Intn(10) {
		case 0:
			n = 0 // 空分块
		case 1:
			n = 1 // 单字节分块
		default:
			n = 1 + rng.Intn(len(data)-pos)
		}
		chunks = append(chunks, data[pos:pos+n])
		pos += n
	}
	return chunks
}

// 分块链式推进必须与一次性计算逐位一致：任意切分（含空块、单字节块、
// 不等长末块）、任意合法参数档（含 refIn!=refOut 混合档、非字节宽度档、
// xor_out 非零档）、双引擎及跨引擎混用。
func TestChunkedMatchesOneShot(t *testing.T) {
	rng := rand.New(rand.NewSource(31337))
	engines := []Engine{EngineBitwise, EngineTable}
	for iter := 0; iter < 400; iter++ {
		p := randomStreamParams(rng)
		data := make([]byte, rng.Intn(200))
		rng.Read(data)
		chunks := randomSplit(rng, data)

		want := Compute(p, data, EngineTable)
		// 每个分块随机选引擎：两路同余，跨引擎链接也必须成立。
		reg := Begin(p)
		for _, c := range chunks {
			reg = Advance(p, reg, c, engines[rng.Intn(2)])
		}
		if got := Finalize(p, reg); got != want {
			t.Fatalf("iter %d: chunked %#x != one-shot %#x (params %+v, %d chunks)",
				iter, got, want, p, len(chunks))
		}
		// 退化情形：整段切成一块，必须与单次接口结果一致。
		if one := Finalize(p, Advance(p, Begin(p), data, EngineTable)); one != want {
			t.Fatalf("iter %d: single-chunk %#x != one-shot %#x", iter, one, want)
		}
	}
}

// 内置具名档公开向量：「123456789」按各种切分（含空块、逐字节块）分块推进，
// 合并结果必须逐位等于 catalog 标准余数，双引擎一致。
func TestChunkedBuiltinVectors(t *testing.T) {
	data := StandardVector
	splits := [][]int{
		{9},            // 退化：整段一块
		{1, 8}, {8, 1}, // 首/末块为单字节
		{3, 3, 3}, {4, 5}, // 均匀与不均匀切分
		{0, 9}, {9, 0}, // 首块/末块为空
		{0, 0, 9}, {2, 0, 7}, // 中间夹空块
		{1, 1, 1, 1, 1, 1, 1, 1, 1}, // 全部单字节
	}
	for _, prof := range ListProfiles() {
		for _, split := range splits {
			sum := 0
			for _, n := range split {
				sum += n
			}
			if sum != len(data) {
				t.Fatalf("bad split %v", split)
			}
			for _, eng := range []Engine{EngineBitwise, EngineTable} {
				reg := Begin(prof.Params)
				pos := 0
				for _, n := range split {
					reg = Advance(prof.Params, reg, data[pos:pos+n], eng)
					pos += n
				}
				if got := Finalize(prof.Params, reg); got != prof.Check {
					t.Fatalf("%s/%s split %v: got %#x, want catalog %#x",
						prof.Name, eng, split, got, prof.Check)
				}
			}
		}
	}
}

// 分块路径下翻转任意分块的任意一个比特，合并出的校验码必须改变
// （定长消息的单比特错误必然被 CRC 检出），且对原数据校验判失败。
func TestChunkedBitFlipChangesResult(t *testing.T) {
	data := []byte("chunked tamper evidence: flip any bit in any chunk")
	for _, prof := range ListProfiles() {
		chunks := [][]byte{data[:10], data[10:30], data[30:]}
		merge := func(chs [][]byte) uint64 {
			reg := Begin(prof.Params)
			for _, c := range chs {
				reg = Advance(prof.Params, reg, c, EngineTable)
			}
			return Finalize(prof.Params, reg)
		}
		good := merge(chunks)
		if good != Compute(prof.Params, data, EngineTable) {
			t.Fatalf("%s: chunked merge != one-shot", prof.Name)
		}
		for ci := range chunks {
			for bit := 0; bit < len(chunks[ci])*8; bit++ {
				bad := append([]byte(nil), chunks[ci]...)
				bad[bit/8] ^= 1 << (bit % 8)
				tampered := [][]byte{chunks[0], chunks[1], chunks[2]}
				tampered[ci] = bad
				got := merge(tampered)
				if got == good {
					t.Fatalf("%s: chunk %d bit %d flip did not change checksum",
						prof.Name, ci, bit)
				}
				if _, ok := Verify(prof.Params, data, got, EngineTable); ok {
					t.Fatalf("%s: chunk %d bit %d flip: tampered check accepted for original data",
						prof.Name, ci, bit)
				}
			}
		}
	}
}

// 空流：一个分块都不提交，直接 Begin→Finalize，必须等于单次接口的空载荷结果。
func TestChunkedEmptyStream(t *testing.T) {
	for _, prof := range ListProfiles() {
		got := Finalize(prof.Params, Begin(prof.Params))
		want := Compute(prof.Params, nil, EngineTable)
		if got != want {
			t.Fatalf("%s: empty stream %#x != one-shot empty %#x", prof.Name, got, want)
		}
	}
}
