package crc

import (
	"errors"
	"sort"
	"sync"
)

// ErrUnknownProfile 表示调用方引用了未登记的参数档名。
// 未知档名一律明确报错，绝不猜测或退回默认档。
var ErrUnknownProfile = errors.New("unknown CRC profile")

// Profile 是一个已登记的具名参数档，附带说明与公开测试向量。
type Profile struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Params      Params `json:"params"`
	// Check 是公开测试向量 ASCII「123456789」在该档下的标准校验码
	// （与 CRC RevEng / zlib catalog 公布值逐位一致）。
	Check uint64 `json:"check"`
}

// registry 是只读注册表：服务启动时一次性建好，之后只有并发读，
// 每次请求都只携带自己的数据，不存在跨请求的余数残留。
var (
	registryOnce sync.Once
	registry     map[string]Profile
)

// 内置档的参数取自 CRC RevEng catalog（https://reveng.sourceforge.io/crc-catalogue/），
// 名称也沿用 catalog 名，方便对照权威资料。
var builtinProfiles = []Profile{
	{
		Name:        "CRC-8",
		Description: "CRC-8/SMBus：width=8 poly=0x07 init=0x00 refin=false refout=false xorout=0x00",
		Params:      Params{Width: 8, Poly: 0x07, Init: 0x00, RefIn: false, RefOut: false, XorOut: 0x00},
		Check:       0xF4,
	},
	{
		Name:        "CRC-8/MAXIM",
		Description: "CRC-8/MAXIM (Dallas 1-Wire)：width=8 poly=0x31 init=0x00 refin=true refout=true xorout=0x00",
		Params:      Params{Width: 8, Poly: 0x31, Init: 0x00, RefIn: true, RefOut: true, XorOut: 0x00},
		Check:       0xA1,
	},
	{
		Name:        "CRC-16/CCITT-FALSE",
		Description: "CRC-16/CCITT-FALSE：width=16 poly=0x1021 init=0xffff refin=false refout=false xorout=0x0000",
		Params:      Params{Width: 16, Poly: 0x1021, Init: 0xffff, RefIn: false, RefOut: false, XorOut: 0x0000},
		Check:       0x29B1,
	},
	{
		Name:        "CRC-16/KERMIT",
		Description: "CRC-16/KERMIT：width=16 poly=0x1021 init=0x0000 refin=true refout=true xorout=0x0000",
		Params:      Params{Width: 16, Poly: 0x1021, Init: 0x0000, RefIn: true, RefOut: true, XorOut: 0x0000},
		Check:       0x2189,
	},
	{
		Name:        "CRC-16/MODBUS",
		Description: "CRC-16/MODBUS：width=16 poly=0x8005 init=0xffff refin=true refout=true xorout=0x0000",
		Params:      Params{Width: 16, Poly: 0x8005, Init: 0xffff, RefIn: true, RefOut: true, XorOut: 0x0000},
		Check:       0x4B37,
	},
	{
		Name:        "CRC-32/ISO-HDLC",
		Description: "CRC-32/ISO-HDLC (zlib/以太网)：width=32 poly=0x04c11db7 init=0xffffffff refin=true refout=true xorout=0xffffffff",
		Params:      Params{Width: 32, Poly: 0x04C11DB7, Init: 0xFFFFFFFF, RefIn: true, RefOut: true, XorOut: 0xFFFFFFFF},
		Check:       0xCBF43926,
	},
}

func initRegistry() {
	registryOnce.Do(func() {
		registry = make(map[string]Profile, len(builtinProfiles))
		for _, prof := range builtinProfiles {
			if err := prof.Params.Validate(); err != nil {
				panic("crc: invalid builtin profile " + prof.Name + ": " + err.Error())
			}
			registry[prof.Name] = prof
		}
	})
}

// GetProfile 返回具名参数档；未登记时返回 ErrUnknownProfile。
func GetProfile(name string) (Profile, error) {
	initRegistry()
	prof, ok := registry[name]
	if !ok {
		return Profile{}, ErrUnknownProfile
	}
	return prof, nil
}

// ListProfiles 按名称排序列出全部已登记参数档。
func ListProfiles() []Profile {
	initRegistry()
	out := make([]Profile, 0, len(registry))
	for _, prof := range registry {
		out = append(out, prof)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// StandardVector 是公开测试向量：ASCII「123456789」。
var StandardVector = []byte("123456789")
