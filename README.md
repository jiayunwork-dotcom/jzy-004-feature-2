# CRC 核算服务（crc-service）

一个**可独立部署的纯服务端循环冗余校验（CRC）核算服务**。上游系统把待传输
或待落盘的数据交给它：

- **编码**：按指定参数档算出固定位宽的 CRC 校验码；
- **校验**：把「数据 + 校验码」交回，重新做一遍多项式除法，余数为零即通过，
  否则判为被篡改或损坏；
- **分块流式核算**：把长数据拆成有序分块逐块提交、无状态推进，合并出与整段
  一次性计算逐位相同的校验码；
- **批量核算**：一次请求算出多条独立载荷各自的校验码，单条失败独立定位。

不涉及登录、账户、前端页面；不是文件同步器，也不是纠错码库。
仅依赖 Go 标准库，无第三方运行时依赖。

- 语言：Go（模块 `crcservice`）
- 默认监听：`:8080`（可用环境变量 `CRC_LISTEN_ADDR` 覆盖）
- 编码：HTTP + JSON

---

## 1. 数据与校验码格式（固定约定）

为避免二义性，服务**固定**使用以下两种编码，不接受其它形式：

| 字段 | 格式 | 说明 |
|------|------|------|
| `data`（载荷） | **标准 base64，RFC 4648，带填充**（Go `StdEncoding`） | 空字符串 `""` 表示**空载荷**，合法且有确定校验码 |
| `checksum`（校验码） | **定长、零填充小写十六进制** | 位数固定为 `ceil(width/4)`，如 8 位→2 位、16 位→4 位、32 位→8 位 |

不符合格式的输入会在**开始计算之前**返回格式错误（见错误码
`DATA_FORMAT_ERROR` / `CHECKSUM_FORMAT_ERROR`）。

> 例如 ASCII `123456789` 的 base64 是 `MTIzNDU2Nzg5`；
> CRC-16/CCITT-FALSE 对它的校验码是 `29b1`。

---

## 2. 参数档（CRC 约定的完整描述）

每一档完整描述一种 CRC 算法，字段语义与
[CRC RevEng / zlib catalog（Rocksoft 模型）](https://reveng.sourceforge.io/crc-catalogue/)
一致：

| 字段 | 含义 |
|------|------|
| `width` | CRC 位宽（寄存器位数），范围 **8–64** |
| `poly` | 生成多项式，MSB-first 规范表示，隐去最高次项；范围 `1 .. 2^width-1`，最低位必须为 1 |
| `init` | 寄存器初值，范围 `0 .. 2^width-1` |
| `ref_in` | 输入是否逐字节按位反转（LSB-first 处理） |
| `ref_out` | 输出是否按位反转 |
| `xor_out` | 最终异或值，范围 `0 .. 2^width-1` |

**反转语义在实现中只解释一次**，编码与校验两侧共用同一套逻辑。
`ref_in=true` 时走 LSB-first 反射除法：进入除法前，**多项式与寄存器初值都按
width 位反转**；寄存器值天然已处于“输出反射后”的方向，因此末级反射仅当
`ref_out != ref_in` 时才进行。对字节宽度且初值为全 0/全 1 的常见标准档，
反转初值后不变，所以这与 zlib `crc32`、CRC-16/MODBUS 等标准反射实现的结果
逐位一致；显式处理反转初值则同时保证了非字节宽度、任意初值的临时档也与
Rocksoft 规范模型逐位一致（由独立参考实现交叉验证）。

### 内置具名档

| 档名 | width | poly | init | ref_in | ref_out | xor_out | `123456789` 标准余数 |
|------|------:|-----:|-----:|:------:|:-------:|--------:|----------------------|
| `CRC-8` | 8 | `0x07` | `0x00` | 否 | 否 | `0x00` | **`f4`** |
| `CRC-8/MAXIM` | 8 | `0x31` | `0x00` | 是 | 是 | `0x00` | **`a1`** |
| `CRC-16/CCITT-FALSE` | 16 | `0x1021` | `0xffff` | 否 | 否 | `0x0000` | **`29b1`** |
| `CRC-16/KERMIT` | 16 | `0x1021` | `0x0000` | 是 | 是 | `0x0000` | **`2189`** |
| `CRC-16/MODBUS` | 16 | `0x8005` | `0xffff` | 是 | 是 | `0x0000` | **`4b37`** |
| `CRC-32/ISO-HDLC` | 32 | `0x04c11db7` | `0xffffffff` | 是 | 是 | `0xffffffff` | **`cbf43926`** |

覆盖了要求的至少一个 8 位宽与一个 16 位宽常见标准档。

调用方也可以在请求里用 `params` **直接给出五项约定临时构造一档**
（`width/poly/init/xor_out` 既可传 JSON 数字，也可传带 `0x` 前缀的字符串）。
非法的位宽、多项式取值、越界的 init/xor_out 都会在计算前被拒绝。
`profile` 与 `params` 二选一，同时给或都不给都是错误。

### 除法引擎

服务内部提供两条除法路径，对同一输入**严格同余**：

- `table`（默认）：按字节查 256 项表；
- `bitwise`：按位逐比特长除法。

可在请求里用 `"engine": "bitwise" | "table"` 选择，主要用于交叉核对。

---

## 3. HTTP 接口

### `GET /healthz`

基本运行状态，供监控与容器健康检查采集。

```json
{"status":"ok","version":"1.1.0","profiles":6,"up_since":"...","uptime_seconds":12}
```

### `GET /metrics`

[Prometheus 文本格式](https://prometheus.io/docs/instrumenting/exposition_formats/)
指标：`crc_http_requests_total`、按结构化错误码计数的
`crc_http_errors_total`、`crc_http_request_duration_seconds`（直方图）、
`crc_requests_in_flight`（在途请求）。

### `GET /api/v1/profiles`

列出全部已登记参数档及其**完整约定**，并附 `123456789` 标准余数。

### `GET /api/v1/vectors`

预置的**公开测试向量算例**：每档给出输入 ASCII、对应 base64 与权威标准余数，
一眼即可核对实现是否正确。

### `POST /api/v1/checksums`（计算校验码）

请求：

```json
{ "profile": "CRC-16/CCITT-FALSE", "data": "MTIzNDU2Nzg5" }
```

响应：

```json
{ "profile": "CRC-16/CCITT-FALSE", "width": 16, "check": "29b1", "engine": "table" }
```

显式临时档：

```json
{
  "params": {"width": 16, "poly": "0x1021", "init": "0xffff",
             "ref_in": false, "ref_out": false, "xor_out": "0x0"},
  "data": "MTIzNDU2Nzg5"
}
```

空载荷：`{"profile":"CRC-8","data":""}` →
`{"...","width":8,"check":"00",...}`（确定值，不报错、不返回空串）。

### `POST /api/v1/verify`（验证数据 + 校验码）

请求：

```json
{ "profile": "CRC-16/CCITT-FALSE", "data": "MTIzNDU2Nzg5", "checksum": "29b1" }
```

响应（正确码字余数为全 0）：

```json
{ "profile": "CRC-16/CCITT-FALSE", "width": 16, "valid": true,
  "residual": "0000", "engine": "table" }
```

数据或校验码任意一个比特被翻转，都会得到非零余数：

```json
{ "width": 16, "valid": false, "residual": "9e91", "engine": "table" }
```

### 校验原理

校验端把提交的校验码先撤销 `xor_out` 与末级反射，恢复成除法寄存器空间里的
原始余数，再把它作为校验字段按该档位序（MSB-first 或 LSB-first）追加到数据
之后继续做长除法。正确码字的**最终余数恒为零**；任何比特错误都会使余数非零。

### `POST /api/v1/chunks`（大载荷分块流式核算）

把一段很长的数据拆成若干**有序分块**逐块提交，最后合并出与「整段一次性算出」
**逐位相同**的校验码。服务**不在服务端保存任何分块进度**：跨块推进所需的中
间状态（已消费字节偏移 + 除法寄存器值）封装在不透明令牌 `state` 里，由调用
方在每次请求中回传，服务只做纯函数式的「在给定状态上吃掉这一块、吐出新状态」。

每个分块请求：

```json
{
  "profile": "CRC-32/ISO-HDLC",   // 或 "params": {...}，与单次接口同一套解析
  "engine": "table",               // 可选；同一段流的不同分块可混用双引擎
  "offset": 0,                     // 必填：本分块首字节在整段数据中的偏移
  "state": "v1....",               // 上一块响应的令牌；首块省略（此时 offset 必须为 0）
  "data": "MTIz",                  // 本分块载荷（标准 base64，空串 = 空分块）
  "final": false                   // true 时收尾，额外返回整段校验码
}
```

响应：

```json
{ "profile": "CRC-32/ISO-HDLC", "width": 32, "engine": "table",
  "offset": 0, "next_offset": 3, "bytes": 3,
  "state": "v1.AQAAAA...（下一块原样回传）",
  "check": "cbf43926" }
```

`check` 仅在 `final: true` 时返回。完整示例（`123456789` 切成
`123`/`4567`/`89` 三块）：

```
POST /api/v1/chunks {"profile":"CRC-32/ISO-HDLC","offset":0,"data":"MTIz"}
  → {"offset":0,"next_offset":3,"state":"v1.A..."}
POST /api/v1/chunks {"profile":"CRC-32/ISO-HDLC","offset":3,"state":"v1.A...","data":"NDU2Nw=="}
  → {"offset":3,"next_offset":7,"state":"v1.B..."}
POST /api/v1/chunks {"profile":"CRC-32/ISO-HDLC","offset":7,"state":"v1.B...","data":"ODk=","final":true}
  → {"offset":7,"next_offset":9,"state":"v1.C...","check":"cbf43926"}
```

合并结果 `cbf43926` 与一次性提交 `MTIzNDU2Nzg5` 完全相同。

**数学正确性**：`init` 只在首块生效一次；输入反转是逐字节的固有处理；
输出反转与 `xor_out` 只在 `final` 收尾时生效一次——绝不在分块边界重复
作用。分块链与一次性除法是同一条递推，因此对任意合法参数档（含
`ref_in != ref_out` 混合档、非字节宽度临时档、`xor_out` 非零档）都逐位一致。
空分块、单字节分块、末块长度不同都能正确合并；整段切成一块（退化情形）
与单次接口结果一致。

**乱序与重传**：本服务选择「**依据定位信息拒绝无法安放的分块**」。
每个请求必须显式携带 `offset`，服务将其与令牌内记录的流位置比对：

- 偏移不符（乱序、错位、拿着过期令牌重复旧块）→ `422 STATE_OFFSET_MISMATCH`；
- 用**完全相同**的 `(state, offset, data)` 重传（如响应丢失后的重试）是
  **幂等**的，返回逐位相同的结果，不影响最终合并值。

**状态令牌的完整性**：令牌格式为 `v1.<base64url 载荷>.<base64url MAC>`，
载荷含偏移、寄存器值与参数档指纹，整体由 **HMAC-SHA256（截断 128 位）**
保护。任何篡改或凭空伪造 → `400 STATE_FORMAT_ERROR`；把甲参数档的令牌
拿去乙档续算 → `422 STATE_PARAMS_MISMATCH`。令牌不含机密（寄存器值本可
由调用方自己的数据推出），故只做完整性保护、不加密。MAC 密钥取自环境变量
**`CRC_STATE_KEY`**；未配置时使用内置默认密钥（仅完整性用途）。多副本部署
如需跨实例识别同一令牌，应为所有副本配置相同的 `CRC_STATE_KEY`。

### `POST /api/v1/checksums/batch`（批量核算）

一次请求提交多条独立的 (参数档, 载荷) 组合，返回每条各自的校验码。
每个条目的字段与单次编码接口完全相同，共享同一套参数解析、格式校验与
错误码语义；单批上限 256 条。

请求：

```json
{ "items": [
    { "profile": "CRC-8", "data": "MTIzNDU2Nzg5" },
    { "params": {"width": 16, "poly": "0x1021", "init": "0xffff",
                 "ref_in": false, "ref_out": false, "xor_out": "0x0"},
      "data": "aGVsbG8=", "engine": "bitwise" },
    { "profile": "NOPE", "data": "" }
] }
```

响应（只要信封合法，整体恒为 200；各条目成败互不影响）：

```json
{ "results": [
    { "index": 0, "ok": true, "profile": "CRC-8", "width": 8,
      "check": "f4", "engine": "table" },
    { "index": 1, "ok": true, "width": 16, "check": "b1f3", "engine": "bitwise" },
    { "index": 2, "ok": false,
      "error": { "code": "UNKNOWN_PROFILE",
                 "detail": "profile 'NOPE' is not registered; ..." } }
] }
```

单条失败通过 `index` 定位到具体条目，并给出与单次接口一致的结构化错误码；
不会整批报错，也不会静默丢弃。每条成功结果与逐条调用单次接口逐位一致。

---

## 4. 错误响应（结构化、区分类型）

所有非法输入都返回非 2xx 与统一结构：

```json
{ "error": { "code": "UNKNOWN_PROFILE", "detail": "profile 'CRC-X' is not registered; ..." } }
```

| code | 典型 HTTP 状态 | 含义 |
|------|:--------------:|------|
| `INVALID_JSON` | 400 | 不是合法 JSON / 含未知字段 / 多个 JSON 值 |
| `PROFILE_AND_PARAMS` | 400 | `profile` 与 `params` 同时给出 |
| `MISSING_PROFILE` | 400 | `profile` 与 `params` 都没给 |
| `UNKNOWN_PROFILE` | 404 | **未登记档名，明确报错，绝不猜测** |
| `INVALID_PARAMETER` | 400/422 | 显式参数缺字段或位宽/多项式/init/xor_out 越界非法 |
| `INVALID_ENGINE` | 400 | `engine` 取值不支持 |
| `DATA_FORMAT_ERROR` | 400 | `data` 不是合法标准 base64 |
| `CHECKSUM_FORMAT_ERROR` | 400/422 | `checksum` 非十六进制、位数不对或超出位宽 |
| `STATE_FORMAT_ERROR` | 400 | `state` 令牌无法解码或未通过完整性校验（篡改/伪造） |
| `STATE_PARAMS_MISMATCH` | 422 | `state` 令牌属于另一个参数档 |
| `STATE_OFFSET_MISMATCH` | 422 | 分块偏移与流位置不符（乱序/错位重传），分块无法安放 |
| `BATCH_EMPTY` | 400 | 批量请求 `items` 缺失或为空 |
| `BATCH_TOO_LARGE` | 422 | 批量请求条目数超过单批上限（256） |
| `METHOD_NOT_ALLOWED` | 405 | HTTP 方法不对 |
| `NOT_FOUND` | 404 | 路径不存在 |

---

## 5. 无状态保证

每次请求的 CRC 计算都是纯函数：数据、起始寄存器、中间余数全部是请求内的
局部变量；参数注册表启动后只读，256 项查表是不可变共享缓存。因此**不存在上一
笔请求的中间余数污染下一笔结果**的可能。服务可随意水平扩容、并发处理。

分块流式核算同样无状态：服务**不为任何会话保存分块进度或中间余数**，跨块
状态全部封装在调用方回传的 `state` 令牌里（带 HMAC 完整性保护，见上节）。
`CRC_STATE_KEY` 只是令牌的完整性密钥，不是会话状态；任意副本都能处理同一
段流的任意一块（多副本时配置相同密钥即可），请求之间不存在任何服务端串扰。

---

## 6. 本地运行

需要 Go 1.23+（仅标准库）。

```bash
go test ./...                       # 运行全部自动化测试
go run ./cmd/crcsrv                 # 默认 :8080
CRC_LISTEN_ADDR=":9090" go run ./cmd/crcsrv
```

环境变量：

| 变量 | 默认 | 说明 |
|------|------|------|
| `CRC_LISTEN_ADDR` | `:8080` | HTTP 监听地址 |
| `CRC_STATE_KEY` | 内置默认密钥 | 分块流式状态令牌的 HMAC 完整性密钥；多副本部署应显式配置为同一值 |

快速核对标准向量：

```bash
curl -s localhost:8080/api/v1/vectors
curl -s -XPOST localhost:8080/api/v1/checksums \
  -H 'Content-Type: application/json' \
  -d '{"profile":"CRC-16/CCITT-FALSE","data":"MTIzNDU2Nzg5"}'
# => "check":"29b1"
```

---

## 7. Docker 一键构建并启动

```bash
# 方式一：docker compose（含健康检查与自动重启）
docker compose up --build -d
docker compose logs -f
docker compose down

# 方式二：原生 docker
docker build -t crc-service:1.1.0 .
docker run -d --name crc-service -p 8080:8080 \
  -e CRC_LISTEN_ADDR=":8080" crc-service:1.1.0
# 多副本部署分块流式时，为所有副本配置同一令牌密钥：
#   -e CRC_STATE_KEY="your-shared-integrity-key"
```

运行镜像基于 `gcr.io/distroless/static`，内含一个静态链接的非 root 二进制，
攻击面小；容器健康检查由二进制自带的
`/crcsrv -healthcheck-uri http://127.0.0.1:8080/healthz` 完成，不依赖
shell/curl。

---

## 8. 自动化测试覆盖的关键行为

`internal/crc` 与 `internal/api` 下的测试覆盖：

1. **公开向量比对**：所有内置档对 ASCII `123456789` 的余数逐位等于 catalog
   标准值（`f4 / a1 / 29b1 / 2189 / 4b37 / cbf43926`）；
2. **编码后自校验**：任意数据（含空载荷）编码后交校验接口余数为 0、判通过；
3. **单比特翻转必失败**：穷举翻转数据的每一比特及校验码的每一比特，全部判失败；
4. **不同宽度档余数相异**：8 位与 16 位档对同一数据的校验码不同；
5. **输入/输出反转两侧一致**：覆盖 `ref_in/ref_out` 四种组合（含二者不一致），
   编码/校验自洽且翻转必失败；
6. **按位与查表两路同余**：内置档 + 数百组随机参数档/随机载荷逐位相等，
   并含 8–64 任意位宽（含非字节宽度）的往返与翻转验证；另用一份不共享实现
   代码的**独立 Rocksoft 规范参考实现**交叉核对全部反转组合；
7. **空载荷确定值**：可重复、定长非空、可被验证（如 CRC-8→`00`、
   CCITT-FALSE→`ffff`、CRC-32→`00000000`）；
8. **并发互不串扰**：包级 16 goroutine / 2000 任务、HTTP 级 32×50 混合请求，
   结果始终等于串行参考值且自校验通过；
9. **分块合并与整体一致**：随机参数档（含混合反转、非字节宽度、xor_out 非零）
   × 随机切分（含空块、单字节块、不等长末块）× 双引擎混用，链式合并结果与
   一次性计算逐位一致；内置档公开向量按多种切分分块合并仍等于 catalog 值；
   整段单块退化、空流（零块直接收尾）均与单次接口一致；
10. **乱序/重传**：乱序或错位分块被 `STATE_OFFSET_MISMATCH` 明确拒绝；
    相同 (state, offset, data) 重传幂等且不影响最终结果；篡改令牌、跨参数档
    令牌、跨密钥实例令牌分别被 `STATE_FORMAT_ERROR` / `STATE_PARAMS_MISMATCH`
    拒绝；翻转合并前任意一块的任意比特，合并校验码必变且对原数据校验判失败；
11. **批量与逐条一致**：批量结果与逐条单次调用逐位相同；单条失败按 `index`
    定位并给出与单次接口一致的错误码，其余条目不受影响；信封级错误
    （空批、超上限、非法 JSON）在计算前拒绝；
12. 另有非法显式参数拒绝、未知档名报错、base64/十六进制格式错误、
    Prometheus 指标等接口级测试。

---

## 9. 目录结构

```
cmd/crcsrv/          程序入口（HTTP server、优雅关停、容器自检模式）
internal/crc/        CRC 核心：参数档与校验、按位/查表双引擎、注册表、十六进制、
                     分块流式原语（Begin/Advance/Finalize）
internal/api/        HTTP/JSON 接口、结构化错误、分块状态令牌（HMAC 完整性）、
                     批量核算、Prometheus 指标
Dockerfile           多阶段静态构建（distroless 运行镜像）
docker-compose.yml   一键构建启动 + 健康检查
```
