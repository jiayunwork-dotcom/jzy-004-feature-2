package api

import (
	"strings"
	"testing"

	"crcservice/internal/crc"
)

// 状态令牌编解码：往返一致；载荷任何字段都参与 MAC（改一个字段值重新
// 编码能过，但手工拼凑/改字节/换密钥必败）。
func TestStreamStateCodecRoundTrip(t *testing.T) {
	key := []byte("codec-test-key")
	profs := crc.ListProfiles()
	for _, prof := range profs {
		st := streamState{
			params:   prof.Params,
			profile:  prof.Name,
			offset:   123456789,
			register: crc.Mask(prof.Params.Width), // 边界：全 1 寄存器
		}
		tok := encodeStreamState(st, key)
		got, err := decodeStreamState(tok, key)
		if err != nil {
			t.Fatalf("%s: decode failed: %v", prof.Name, err)
		}
		if got != st {
			t.Fatalf("%s: round trip %+v != %+v", prof.Name, got, st)
		}
	}

	// 临时档（非字节宽度、混合反转）同样往返一致。
	p := crc.Params{Width: 13, Poly: 0x1f35, Init: 0x123, RefIn: true, RefOut: false, XorOut: 0x1c2}
	st := streamState{params: p, profile: "", offset: 0, register: 0x1abc}
	got, err := decodeStreamState(encodeStreamState(st, key), key)
	if err != nil || got != st {
		t.Fatalf("ad-hoc round trip: %+v %v", got, err)
	}
}

// 篡改检测：令牌任何位置的单字符改动都必须被 STATE_INVALID 拒绝；
// 换密钥、改版本、手工构造合法结构但无密钥，都必败。
func TestStreamStateCodecTamperEvidence(t *testing.T) {
	key := []byte("tamper-key-A")
	otherKey := []byte("tamper-key-B")
	st := streamState{
		params:   crc.Params{Width: 16, Poly: 0x1021, Init: 0xffff, XorOut: 0},
		profile:  "CRC-16/CCITT-FALSE",
		offset:   42,
		register: 0xabcd,
	}
	tok := encodeStreamState(st, key)

	// 逐字符扰动：把每个位置换成另一个合法 base64url 字符，全部必须失败。
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for i := 0; i < len(tok); i++ {
		if tok[i] == '.' {
			continue
		}
		repl := alphabet[0]
		if tok[i] == repl {
			repl = alphabet[1]
		}
		mut := tok[:i] + string(repl) + tok[i+1:]
		if _, err := decodeStreamState(mut, key); err == nil {
			t.Fatalf("mutation at %d accepted: %q", i, mut)
		}
	}

	// 换密钥必败。
	if _, err := decodeStreamState(tok, otherKey); err == nil {
		t.Fatal("token verified under a different key")
	}
	// 版本不符必败。
	if _, err := decodeStreamState("v2."+strings.SplitN(tok, ".", 2)[1], key); err == nil {
		t.Fatal("wrong version accepted")
	}
	// 无密钥伪造：即使结构合法（攻击者知道格式），没有密钥也算不出 MAC。
	forged := "v1." + strings.Split(tok, ".")[1] + "." + strings.Repeat("A", 43)
	if _, err := decodeStreamState(forged, key); err == nil {
		t.Fatal("forged MAC accepted")
	}
}

// 防御性校验：合法 MAC 但内容越界（非法参数档、寄存器越位宽）也拒绝。
// 正常流程产生不了这种令牌，这里用密钥直接构造来锁死解码端的校验。
func TestStreamStateCodecRevalidatesContent(t *testing.T) {
	key := []byte("content-check-key")
	good := streamState{
		params:   crc.Params{Width: 8, Poly: 0x07},
		offset:   1,
		register: 0,
	}
	// 寄存器超出位宽。
	bad := good
	bad.register = 0x100
	if _, err := decodeStreamState(encodeStreamState(bad, key), key); err == nil {
		t.Fatal("out-of-width register accepted")
	}
	// 非法参数档（偶数多项式）。
	bad = good
	bad.params.Poly = 0x08
	if _, err := decodeStreamState(encodeStreamState(bad, key), key); err == nil {
		t.Fatal("invalid params accepted")
	}
	// 宽度越界。
	bad = good
	bad.params.Width = 3
	if _, err := decodeStreamState(encodeStreamState(bad, key), key); err == nil {
		t.Fatal("out-of-range width accepted")
	}
}
