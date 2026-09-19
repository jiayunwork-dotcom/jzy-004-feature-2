package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"strings"

	"crcservice/internal/crc"
)

// 分块流式核算的中间状态令牌。
//
// 服务不在服务端保存任何会话进度：跨分块推进所需的全部中间状态
// （参数档、已消费字节偏移、除法寄存器当前值）打包进一个不透明令牌，
// 由调用方在每次请求里回传。令牌带 HMAC-SHA256 完整性校验：
//
//	v1.<base64url(payload)>.<base64url(hmac-sha256(key, domainSep‖payload))>
//
// 因此令牌对调用方不可伪造、不可篡改——任何改动的令牌都会在计算前以
// STATE_INVALID 拒绝。密钥来自环境变量 CRC_STATE_KEY（多实例部署必须在
// 所有实例上配置同一密钥，令牌才能跨实例/跨重启流通）；未配置时使用
// 进程启动时生成的随机密钥，此时令牌随进程重启失效。

// stateKeyEnv 是配置流式状态令牌密钥的环境变量名。
const stateKeyEnv = "CRC_STATE_KEY"

// streamState 是一次流式核算在请求之间由调用方携带的全部中间状态。
type streamState struct {
	params   crc.Params // 起始请求确定的参数档（令牌内已认证，防止换档续算）
	profile  string     // 起始请求使用的具名档名（仅用于回显，可为空）
	offset   uint64     // 已消费字节数，即下一块必须携带的偏移
	register uint64     // 除法寄存器当前值（未做末级反射与 xor_out）
}

// 令牌载荷的二进制布局（全部大端定长字段 + 变长档名）：
//
//	[0]      结构版本，固定 1
//	[1]      width
//	[2:10]   poly
//	[10:18]  init
//	[18]     标志位：bit0=ref_in, bit1=ref_out（其余位必须为 0）
//	[19:27]  xor_out
//	[27:35]  offset（下一块必须携带的偏移）
//	[35:43]  register
//	[43]     档名长度 n
//	[44:44+n] 档名（可为空）
const (
	streamTokenVersion   = "v1"
	streamStateFixedLen  = 44
	streamStateMaxNameLn = 255
)

// errStreamStateInvalid 表示令牌无法解析或未通过完整性校验。
// 对外统一映射为 STATE_INVALID，不区分具体失败环节（避免给伪造者oracle）。
var errStreamStateInvalid = errors.New("invalid stream state token")

// stateKeyFromEnv 解析流式状态密钥：优先取 CRC_STATE_KEY；未配置时生成
// 进程级随机密钥（单实例可用，重启或横向扩容前必须显式配置共享密钥）。
func stateKeyFromEnv() []byte {
	if k := os.Getenv(stateKeyEnv); k != "" {
		return []byte(k)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("api: cannot generate stream state key: " + err.Error())
	}
	return key
}

// StateKeyConfigured 报告是否已通过 CRC_STATE_KEY 配置固定的流式状态密钥，
// 供启动日志提示运维风险。
func StateKeyConfigured() bool { return os.Getenv(stateKeyEnv) != "" }

// encodeStreamState 把中间状态封装为带完整性校验的不透明令牌。
func encodeStreamState(st streamState, key []byte) string {
	name := st.profile
	if len(name) > streamStateMaxNameLn {
		name = name[:streamStateMaxNameLn] // 档名远短于此，防御性截断
	}
	payload := make([]byte, streamStateFixedLen+len(name))
	payload[0] = 1 // 结构版本
	payload[1] = st.params.Width
	binary.BigEndian.PutUint64(payload[2:10], st.params.Poly)
	binary.BigEndian.PutUint64(payload[10:18], st.params.Init)
	var flags byte
	if st.params.RefIn {
		flags |= 1
	}
	if st.params.RefOut {
		flags |= 2
	}
	payload[18] = flags
	binary.BigEndian.PutUint64(payload[19:27], st.params.XorOut)
	binary.BigEndian.PutUint64(payload[27:35], st.offset)
	binary.BigEndian.PutUint64(payload[35:43], st.register)
	payload[43] = byte(len(name))
	copy(payload[streamStateFixedLen:], name)

	mac := streamStateMAC(key, payload)
	return streamTokenVersion + "." +
		base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac)
}

// streamStateMAC 计算带域分离的 HMAC-SHA256。
func streamStateMAC(key, payload []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte("crcsrv/stream-state/v1\x00"))
	h.Write(payload)
	return h.Sum(nil)
}

// decodeStreamState 解析并校验令牌。任何结构非法、版本不符、MAC 不匹配、
// 参数档非法或寄存器越位宽的情况都返回 errStreamStateInvalid。
func decodeStreamState(token string, key []byte) (streamState, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != streamTokenVersion {
		return streamState{}, errStreamStateInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(payload) < streamStateFixedLen {
		return streamState{}, errStreamStateInvalid
	}
	mac, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(mac) != sha256.Size {
		return streamState{}, errStreamStateInvalid
	}
	if subtle.ConstantTimeCompare(streamStateMAC(key, payload), mac) != 1 {
		return streamState{}, errStreamStateInvalid
	}
	// 以下字段校验针对的是「密钥配置变更/跨版本」等合法 MAC 但内容越界的
	// 边界情形；伪造令牌到不了这里（MAC 已先行拒绝）。
	if payload[0] != 1 {
		return streamState{}, errStreamStateInvalid
	}
	nameLen := int(payload[43])
	if len(payload) != streamStateFixedLen+nameLen {
		return streamState{}, errStreamStateInvalid
	}
	flags := payload[18]
	if flags&^byte(3) != 0 {
		return streamState{}, errStreamStateInvalid
	}
	p := crc.Params{
		Width:  payload[1],
		Poly:   binary.BigEndian.Uint64(payload[2:10]),
		Init:   binary.BigEndian.Uint64(payload[10:18]),
		RefIn:  flags&1 != 0,
		RefOut: flags&2 != 0,
		XorOut: binary.BigEndian.Uint64(payload[19:27]),
	}
	if err := p.Validate(); err != nil {
		return streamState{}, errStreamStateInvalid
	}
	reg := binary.BigEndian.Uint64(payload[35:43])
	if reg > crc.Mask(p.Width) {
		return streamState{}, errStreamStateInvalid
	}
	return streamState{
		params:   p,
		profile:  string(payload[streamStateFixedLen:]),
		offset:   binary.BigEndian.Uint64(payload[27:35]),
		register: reg,
	}, nil
}
