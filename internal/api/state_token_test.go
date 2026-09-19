package api

import (
	"strings"
	"testing"

	"crcservice/internal/crc"
)

func testTokenServer() *Server {
	s := NewServer()
	s.stateKey = []byte("test state key")
	return s
}

func mustFingerprint(t *testing.T, name string) [stateParamsHashLen]byte {
	t.Helper()
	prof, err := crc.GetProfile(name)
	if err != nil {
		t.Fatal(err)
	}
	return paramsFingerprint(prof.Params)
}

// 令牌编解码往返：状态字段必须原样恢复。
func TestStateTokenRoundTrip(t *testing.T) {
	s := testTokenServer()
	st := streamState{offset: 123456789, reg: 0xDEADBEEFCAFE, params: mustFingerprint(t, "CRC-32/ISO-HDLC")}
	tok := s.encodeState(st)
	if !strings.HasPrefix(tok, "v1.") || strings.ContainsAny(tok, "+/=") {
		t.Fatalf("token not in expected opaque url-safe form: %q", tok)
	}
	got, err := s.decodeState(tok)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != st {
		t.Fatalf("round trip mismatch: got %+v want %+v", got, st)
	}
}

// 篡改令牌的任意一段（载荷或 MAC）都必须被完整性校验拒绝。
func TestStateTokenTamperRejected(t *testing.T) {
	s := testTokenServer()
	tok := s.encodeState(streamState{offset: 5, reg: 0xABCD, params: mustFingerprint(t, "CRC-16/KERMIT")})
	parts := strings.Split(tok, ".")

	flip := func(str string, i int) string {
		b := []byte(str)
		if b[i] == 'A' {
			b[i] = 'B'
		} else {
			b[i] = 'A'
		}
		return string(b)
	}
	variants := []string{
		flip(parts[1], 0) + "." + parts[2],                  // 篡改载荷首字符
		parts[1] + "." + flip(parts[2], 3),                  // 篡改 MAC
		"v2." + parts[1] + "." + parts[2],                   // 版本不符
		parts[1],                                            // 缺段
		parts[1] + "." + parts[2] + ".extra",                // 多段
		"!!!.!!!.!!!",                                       // 非法 base64
		strings.Repeat("A", len(parts[1])) + "." + parts[2], // 长度不同的载荷
		"",
	}
	for i, v := range variants {
		if _, err := s.decodeState(v); err == nil {
			t.Fatalf("variant %d accepted: %q", i, v)
		}
	}
}

// 密钥不同的服务实例必须拒绝彼此签发的令牌（伪造/串实例令牌不得通过）。
func TestStateTokenForeignKeyRejected(t *testing.T) {
	a := testTokenServer()
	b := NewServer()
	b.stateKey = []byte("another key")
	tok := a.encodeState(streamState{offset: 1, reg: 2, params: mustFingerprint(t, "CRC-8")})
	if _, err := b.decodeState(tok); err == nil {
		t.Fatal("token signed with a different key was accepted")
	}
}

// 参数档指纹：任一约定字段变化都必须改变指纹。
func TestParamsFingerprintSensitivity(t *testing.T) {
	base := crc.Params{Width: 16, Poly: 0x1021, Init: 0xFFFF, RefIn: false, RefOut: false, XorOut: 0}
	fp := paramsFingerprint(base)
	variants := []crc.Params{
		{Width: 15, Poly: 0x1021, Init: 0xFFFF, XorOut: 0},
		{Width: 16, Poly: 0x1023, Init: 0xFFFF, XorOut: 0},
		{Width: 16, Poly: 0x1021, Init: 0xFFFE, XorOut: 0},
		{Width: 16, Poly: 0x1021, Init: 0xFFFF, RefIn: true, XorOut: 0},
		{Width: 16, Poly: 0x1021, Init: 0xFFFF, RefOut: true, XorOut: 0},
		{Width: 16, Poly: 0x1021, Init: 0xFFFF, XorOut: 1},
	}
	for i, v := range variants {
		if paramsFingerprint(v) == fp {
			t.Fatalf("variant %d did not change fingerprint", i)
		}
	}
}
