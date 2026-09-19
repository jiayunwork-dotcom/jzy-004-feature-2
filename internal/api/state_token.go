package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"strings"

	"crcservice/internal/crc"
)

// 分块流式核算的中间状态令牌。
//
// 服务保持无状态：不在服务端为任何会话保存分块进度或中间余数。跨分块推进
// 所需的全部中间状态（已消费字节偏移、除法寄存器值、参数档指纹）都封装在
// 不透明令牌里，由调用方在下一次请求中回传；服务只做纯函数式的
// 「在给定状态上吃掉这一块、吐出新状态」。
//
// 完整性：令牌带 HMAC-SHA256（截断 128 位）消息认证码。任何比特被篡改、
// 凭空伪造、或把甲参数档的令牌拿去乙参数档续算，都会在计算前被拒绝
// （STATE_FORMAT_ERROR / STATE_PARAMS_MISMATCH），绝不静默接受。
// 令牌不含任何机密（寄存器值本就可由调用方自己的数据推出），因此只做
// 完整性保护、不加密。
//
// 令牌格式（对调用方不透明，禁止自行构造或解析）：
//
//	v1.<base64url(payload)>.<base64url(mac)>
//	payload = version(1) | offset(8, BE) | register(8, BE) | paramsHash(8)
//	mac     = HMAC-SHA256(stateKey, payload)[:16]
const (
	stateTokenVersion  = 1
	stateMACLen        = 16
	statePayloadLen    = 1 + 8 + 8 + 8
	stateParamsHashLen = 8
)

// errStateMalformed 表示令牌结构非法或未通过完整性校验。
var errStateMalformed = errors.New("state token is malformed or fails integrity check")

// defaultStateKey 是未配置 CRC_STATE_KEY 时的内置完整性密钥，只用于令牌的
// 防篡改/防伪造校验。多副本部署如需跨实例识别同一令牌，应通过环境变量
// CRC_STATE_KEY 显式配置同一密钥（见 README）。
var defaultStateKey = []byte("crc-service stream state integrity key v1")

// stateKeyFromEnv 读取部署配置的令牌密钥；未配置时使用内置默认密钥。
func stateKeyFromEnv() []byte {
	if k := strings.TrimSpace(os.Getenv("CRC_STATE_KEY")); k != "" {
		return []byte(k)
	}
	return defaultStateKey
}

// paramsFingerprint 返回参数档的 64 位指纹，把令牌绑定到具体参数档：
// 同一段流的所有分块必须使用完全相同的 profile/params。
func paramsFingerprint(p crc.Params) [stateParamsHashLen]byte {
	var buf [1 + 8 + 8 + 8 + 1]byte
	buf[0] = p.Width
	binary.BigEndian.PutUint64(buf[1:9], p.Poly)
	binary.BigEndian.PutUint64(buf[9:17], p.Init)
	binary.BigEndian.PutUint64(buf[17:25], p.XorOut)
	if p.RefIn {
		buf[25] |= 1
	}
	if p.RefOut {
		buf[25] |= 2
	}
	sum := sha256.Sum256(buf[:])
	var fp [stateParamsHashLen]byte
	copy(fp[:], sum[:stateParamsHashLen])
	return fp
}

// streamState 是令牌中封装的流式中间状态。
type streamState struct {
	offset uint64                   // 已消费的字节数（流位置）
	reg    uint64                   // 除法寄存器当前值（未做末级反射与 xor_out）
	params [stateParamsHashLen]byte // 参数档指纹
}

// encodeState 把中间状态封装为带完整性保护的不透明令牌。
func (s *Server) encodeState(st streamState) string {
	var payload [statePayloadLen]byte
	payload[0] = stateTokenVersion
	binary.BigEndian.PutUint64(payload[1:9], st.offset)
	binary.BigEndian.PutUint64(payload[9:17], st.reg)
	copy(payload[17:25], st.params[:])
	mac := hmac.New(sha256.New, s.stateKey)
	mac.Write(payload[:])
	tag := mac.Sum(nil)[:stateMACLen]
	return "v1." + base64.RawURLEncoding.EncodeToString(payload[:]) + "." +
		base64.RawURLEncoding.EncodeToString(tag)
}

// decodeState 解码并校验令牌。结构非法、版本不符或完整性校验失败
// 一律返回 errStateMalformed（不区分细节，避免给伪造者任何反馈）。
func (s *Server) decodeState(token string) (streamState, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return streamState{}, errStateMalformed
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(payload) != statePayloadLen || payload[0] != stateTokenVersion {
		return streamState{}, errStateMalformed
	}
	tag, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(tag) != stateMACLen {
		return streamState{}, errStateMalformed
	}
	mac := hmac.New(sha256.New, s.stateKey)
	mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil)[:stateMACLen], tag) {
		return streamState{}, errStateMalformed
	}
	var st streamState
	st.offset = binary.BigEndian.Uint64(payload[1:9])
	st.reg = binary.BigEndian.Uint64(payload[9:17])
	copy(st.params[:], payload[17:25])
	return st, nil
}
