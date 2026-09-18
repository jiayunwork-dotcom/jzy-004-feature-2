package crc

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"sync"
	"testing"
)

// 公开测试向量：ASCII「123456789」在每个标准档下必须与 CRC RevEng catalog
// 公布的标准余数逐位一致；按位与查表两条路径必须给出相同结果。
func TestPublicVectors(t *testing.T) {
	for _, prof := range ListProfiles() {
		prof := prof
		t.Run(prof.Name, func(t *testing.T) {
			cb := Compute(prof.Params, StandardVector, EngineBitwise)
			ct := Compute(prof.Params, StandardVector, EngineTable)
			if cb != prof.Check || ct != prof.Check {
				t.Fatalf("%s: bitwise=%#x table=%#x, want standard %#x",
					prof.Name, cb, ct, prof.Check)
			}
			if got := FormatHex(cb, prof.Params.Width); got != FormatHex(prof.Check, prof.Params.Width) {
				t.Fatalf("hex format = %s, want %s", got, FormatHex(prof.Check, prof.Params.Width))
			}
		})
	}
}

// 经典常数交叉核对：zlib CRC-32 对「123456789」= 0xCBF43926，
// 并额外核对其十六进制字节串输入（catalog 常见的第二种核对方式）。
func TestCRC32KnownConstants(t *testing.T) {
	prof, err := GetProfile("CRC-32/ISO-HDLC")
	if err != nil {
		t.Fatal(err)
	}
	if c := Compute(prof.Params, StandardVector, EngineTable); c != 0xCBF43926 {
		t.Fatalf("crc32 check = %#x", c)
	}
	// 空载荷：CRC-32 初值全 1、末值全异或，确定值为 0x00000000。
	if c := Compute(prof.Params, nil, EngineTable); c != 0x00000000 {
		t.Fatalf("crc32(empty) = %#x, want 0x0", c)
	}
}

// 任意数据先编码再把「数据 + 码」交给 Verify，两条路径都必须判通过。
func TestEncodeThenVerifyRoundtrip(t *testing.T) {
	payloads := [][]byte{
		nil,
		{},
		[]byte(""),
		[]byte("a"),
		[]byte("123456789"),
		{0x00, 0xff, 0x10, 0x7f, 0x80},
		mustHex("deadbeefcafebabe"),
	}
	for _, prof := range ListProfiles() {
		for _, eng := range []Engine{EngineBitwise, EngineTable} {
			for i, data := range payloads {
				check := Compute(prof.Params, data, eng)
				residual, ok := Verify(prof.Params, data, check, eng)
				if !ok {
					t.Fatalf("%s/%s payload#%d: expected valid, residual=%#x",
						prof.Name, eng, i, residual)
				}
				if residual != 0 {
					t.Fatalf("%s/%s payload#%d: residual must be zero, got %#x",
						prof.Name, eng, i, residual)
				}
			}
		}
	}
}

// 翻转数据或校验码中的任意一个比特，校验必须失败（不得侥幸通过）。
func TestSingleBitFlipsAlwaysFail(t *testing.T) {
	data := []byte("The quick brown fox jumps over the lazy dog")
	for _, prof := range ListProfiles() {
		check := Compute(prof.Params, data, EngineTable)

		for bit := 0; bit < len(data)*8; bit++ {
			corrupt := append([]byte(nil), data...)
			corrupt[bit/8] ^= 1 << (bit % 8)
			if _, ok := Verify(prof.Params, corrupt, check, EngineTable); ok {
				t.Fatalf("%s: flipping data bit %d was accepted", prof.Name, bit)
			}
		}
		for bit := uint8(0); bit < prof.Params.Width; bit++ {
			badCheck := check ^ (uint64(1) << bit)
			if _, ok := Verify(prof.Params, data, badCheck, EngineTable); ok {
				t.Fatalf("%s: flipping check bit %d was accepted", prof.Name, bit)
			}
		}
	}
}

// 同一段数据在 8 位档与 16 位档下算出的校验码必须不同。
func TestDifferentWidthsDiffer(t *testing.T) {
	data := []byte("123456789")
	p8, _ := GetProfile("CRC-8")
	p16, _ := GetProfile("CRC-16/CCITT-FALSE")
	c8 := Compute(p8.Params, data, EngineTable)
	c16 := Compute(p16.Params, data, EngineTable)
	if c8 == c16 {
		t.Fatalf("CRC-8 and CRC-16 produced identical value %#x", c8)
	}
	if FormatHex(c8, 8) == FormatHex(c16, 16) {
		t.Fatalf("formatted checksums unexpectedly equal")
	}
	// 再用随机数据确认一遍不是巧合。
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 64; i++ {
		b := make([]byte, 1+rng.Intn(32))
		rng.Read(b)
		if Compute(p8.Params, b, EngineTable) == Compute(p16.Params, b, EngineTable) {
			t.Fatalf("width collision on random data %x", b)
		}
	}
}

// 反转语义一致性：同一份参数在编码与校验两侧必须自洽。
// 覆盖 refIn/refOut 的全部四种组合（含 refIn != refOut 这种容易只在一侧
// 实现反转的组合），并对每个比特翻转做失败验证。
func TestReflectionSymmetryAllCombinations(t *testing.T) {
	base := Params{Width: 16, Poly: 0x1021, Init: 0x1234, XorOut: 0x5678}
	data := []byte("reflection symmetry probe 0123")
	for _, refIn := range []bool{false, true} {
		for _, refOut := range []bool{false, true} {
			p := base
			p.RefIn, p.RefOut = refIn, refOut
			for _, eng := range []Engine{EngineBitwise, EngineTable} {
				check := Compute(p, data, eng)
				if _, ok := Verify(p, data, check, eng); !ok {
					t.Fatalf("refIn=%v refOut=%v %s: roundtrip rejected",
						refIn, refOut, eng)
				}
				for bit := uint8(0); bit < p.Width; bit++ {
					if _, ok := Verify(p, data, check^(1<<bit), eng); ok {
						t.Fatalf("refIn=%v refOut=%v %s: check bit %d flip accepted",
							refIn, refOut, eng, bit)
					}
				}
			}
		}
	}
}

// 按位与查表两路对同一输入必须完全同余：公开向量 + 随机档/随机载荷。
func TestBitwiseAndTableAgree(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	for _, prof := range ListProfiles() {
		data := []byte("cross engine agreement")
		cb := Compute(prof.Params, data, EngineBitwise)
		ct := Compute(prof.Params, data, EngineTable)
		if cb != ct {
			t.Fatalf("%s: bitwise %#x != table %#x", prof.Name, cb, ct)
		}
	}
	for iter := 0; iter < 200; iter++ {
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
		data := make([]byte, rng.Intn(64))
		rng.Read(data)
		cb := Compute(p, data, EngineBitwise)
		ct := Compute(p, data, EngineTable)
		if cb != ct {
			t.Fatalf("iter %d %+v: bitwise %#x != table %#x", iter, p, cb, ct)
		}
	}
}

// 空载荷不是错误：在每个标准档下都必须返回确定值（可重复、非“空串异常”），
// 且该值能被 Verify 接受。
func TestEmptyPayloadDeterministic(t *testing.T) {
	for _, prof := range ListProfiles() {
		var c1, c2 uint64
		for i := 0; i < 3; i++ {
			c1 = Compute(prof.Params, nil, EngineBitwise)
			c2 = Compute(prof.Params, []byte{}, EngineTable)
		}
		if c1 != c2 {
			t.Fatalf("%s: empty checksum unstable %#x vs %#x", prof.Name, c1, c2)
		}
		s := FormatHex(c1, prof.Params.Width)
		if s == "" || len(s) != HexDigits(prof.Params.Width) {
			t.Fatalf("%s: bad empty checksum representation %q", prof.Name, s)
		}
		if _, ok := Verify(prof.Params, nil, c1, EngineTable); !ok {
			t.Fatalf("%s: empty checksum %#x rejected", prof.Name, c1)
		}
	}

	// 非零初值的 8 位档空载荷也有确定值（CRC-8 init=0 -> 0x00）。
	p8, _ := GetProfile("CRC-8")
	if c := Compute(p8.Params, nil, EngineBitwise); c != 0x00 {
		t.Fatalf("CRC-8(empty) = %#x, want 0x00", c)
	}
	// CRC-16/CCITT-FALSE 空载荷：init=0xFFFF 经过纯移位除法，
	// 确定余数 catalog 记为 0xFFFF。
	p16, _ := GetProfile("CRC-16/CCITT-FALSE")
	if c := Compute(p16.Params, nil, EngineBitwise); c != 0xFFFF {
		t.Fatalf("CRC-16/CCITT-FALSE(empty) = %#x, want 0xffff", c)
	}
}

// 并发下多请求互不串扰：大量 goroutine 用不同档/不同数据反复计算，
// 结果必须始终等于串行参考值。计算全部走局部变量，缓存只读共享。
func TestConcurrentNoCrossContamination(t *testing.T) {
	profs := ListProfiles()
	rng := rand.New(rand.NewSource(123))
	type job struct {
		profIdx int
		data    []byte
		eng     Engine
		want    uint64
	}
	jobs := make([]job, 2000)
	for i := range jobs {
		j := job{
			profIdx: rng.Intn(len(profs)),
			data:    make([]byte, rng.Intn(128)),
			eng:     []Engine{EngineBitwise, EngineTable}[rng.Intn(2)],
		}
		rng.Read(j.data)
		j.want = Compute(profs[j.profIdx].Params, j.data, j.eng)
		jobs[i] = j
	}

	var wg sync.WaitGroup
	errCh := make(chan error, len(jobs))
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for k := worker; k < len(jobs); k += 16 {
				j := jobs[k]
				got := Compute(profs[j.profIdx].Params, j.data, j.eng)
				if got != j.want {
					errCh <- fmt.Errorf("job %d: got %#x want %#x", k, got, j.want)
					return
				}
				if _, ok := Verify(profs[j.profIdx].Params, j.data, got, j.eng); !ok {
					errCh <- fmt.Errorf("job %d: verify failed", k)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for e := range errCh {
		t.Fatal(e)
	}
}

// 显式参数档的非法值必须在计算前被拒绝。
func TestExplicitParamsValidation(t *testing.T) {
	good := Params{Width: 16, Poly: 0x1021, Init: 0x0, RefIn: false, RefOut: false, XorOut: 0x0}
	if err := good.Validate(); err != nil {
		t.Fatalf("good params rejected: %v", err)
	}
	cases := []struct {
		name string
		p    Params
		want error
	}{
		{"width zero", Params{Width: 0, Poly: 0x31}, ErrWidthOutOfRange},
		{"width >64", Params{Width: 65, Poly: 1}, ErrWidthOutOfRange},
		{"width 7 below min", Params{Width: 7, Poly: 1}, ErrWidthOutOfRange},
		{"poly zero", Params{Width: 8, Poly: 0}, ErrPolyOutOfRange},
		{"poly exceeds mask", Params{Width: 8, Poly: 0x100}, ErrPolyOutOfRange},
		{"poly even (no x^0 term)", Params{Width: 8, Poly: 0x30}, ErrPolyEven},
		{"init exceeds mask", Params{Width: 8, Poly: 0x07, Init: 0x100}, ErrInitOutOfRange},
		{"xorout exceeds mask", Params{Width: 8, Poly: 0x07, XorOut: 0x100}, ErrXorOutOfRange},
	}
	for _, tc := range cases {
		if err := tc.p.Validate(); err != tc.want {
			t.Fatalf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
	// 64 位边界：最大多项式合法。
	p64 := Params{Width: 64, Poly: ^uint64(0), Init: ^uint64(0), XorOut: ^uint64(0)}
	if err := p64.Validate(); err != nil {
		t.Fatalf("64-bit params rejected: %v", err)
	}
	c64 := Compute(p64, []byte("boundary"), EngineTable)
	if _, ok := Verify(p64, []byte("boundary"), c64, EngineTable); !ok {
		t.Fatal("64-bit roundtrip failed")
	}
}

// 未知档名必须明确报错。
func TestUnknownProfile(t *testing.T) {
	if _, err := GetProfile("CRC-42/NOPE"); err != ErrUnknownProfile {
		t.Fatalf("got %v, want ErrUnknownProfile", err)
	}
}

// 十六进制表示：定长、零填充、解析往返、非法与越界输入报错。
func TestHexRoundTrip(t *testing.T) {
	cases := []struct {
		width uint8
		v     uint64
		s     string
	}{
		{8, 0xf4, "f4"},
		{8, 0x0, "00"},
		{16, 0x29b1, "29b1"},
		{12, 0xabc, "abc"},
		{13, 0x1fff, "1fff"},
		{32, 0xcbf43926, "cbf43926"},
		{64, 0, "0000000000000000"},
	}
	for _, tc := range cases {
		if s := FormatHex(tc.v, tc.width); s != tc.s {
			t.Fatalf("FormatHex(%#x,%d) = %q, want %q", tc.v, tc.width, s, tc.s)
		}
		got, err := ParseHex(tc.s, tc.width)
		if err != nil || got != tc.v {
			t.Fatalf("ParseHex(%q,%d) = %#x,%v", tc.s, tc.width, got, err)
		}
	}
	for _, bad := range []string{"", "f", "fff", "xyz", "g4"} {
		if _, err := ParseHex(bad, 8); err == nil {
			t.Fatalf("ParseHex(%q,8) should fail", bad)
		}
	}
	// width=12 允许最高半字节 0/1：2abc 超出 12 位掩码。
	if _, err := ParseHex("2abc", 12); err != ErrHexTooLong {
		t.Fatalf("got %v, want ErrHexTooLong", err)
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
