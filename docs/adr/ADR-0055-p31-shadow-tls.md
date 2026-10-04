# ADR-0055：P31 shadow-tls 客户端（v1/v2/v3，ss 插件）+ TLS ClientHello 严格解析修复

- **状态**：已采纳（2026-10-04）
- **对应**：对标表缺口 #6 余项「插件/shadowtls」（SIP003 `plugin=shadow-tls`）
- **相关**：ADR-0048（当时显式列为边界）、ADR-0049/0050（插件形态对照）、ADR-0054；
  NOTES §11.46；对照 `sagernet/sing-shadowtls v0.2.0` 与
  `olicesx/outbound/transport/shadowtls`

## 背景

- dae 出站支持对 ss 节点挂 SIP003 插件：`ss://…?plugin=shadow-tls;host=…;password=…;version=3`。
  shadow-tls 把「伪装 TLS 握手（到真实站点）」与「内层 ss 流量」叠在一条 TCP 上，
  用于对抗主动探测。三个协议版本：
  - v1：TLS（≤1.2）握手后裸 TCP 隧道（无认证、无帧）；
  - v2：任意 TLS 版本握手；客户端首个应用数据前 8 字节 =
    `HMAC-SHA1(password, 服务端握手字节)`，之后按 TLS record（0x17）分帧；
  - v3：ClientHello `session_id` 末 4B 为 `HMAC-SHA1(password, CH 零位)`；
    握手后服务端对加密飞行做 `[mac4][xor(payload)]` 改写，客户端反向还原；
    认证后双向帧带链式 HMAC（`"C"`/`"S"`）。
- 参考实现依赖 Go TLS fork 暴露的 `SessionIDGenerator` 与 `streamWrapper`
  （在握手期把改写帧还原成正常 TLS 记录交给 TLS 栈）。
- 我方 `tls13.rs` 自实现栈本就暴露 ClientHello 全部字段（含 session_id），
  具备实现 v3 的关键条件；`tls.rs`（rustls）可承担 v1 的 TLS 1.2 握手。

## 决策

1. **新模块 `shadowtls.rs`**（客户端）：
   - v1：rustls（`build_rustls_config_tls12`，与参考客户端一致锁 TLS 1.2）握手后
     返回裸隧道；证书按 rustls 常规校验（`allowInsecure=1` 可跳过）。
   - v2：`tls13` 握手；`HashIo` 记录服务端握手字节 → 首帧前置 8B HMAC；
     读方向按 0x17 分帧；**用 TLS 应用读密钥甄别并跳过伪装站的
     NewSessionTicket 等真实 TLS 记录**（参考实现靠 TLS 栈读提前量规避，此为
     显式增强，避免票据被当隧道帧）。
   - v3：`make_hello` 植入 session_id HMAC；`V3HandshakeIo` 在握手期对
     应用数据记录做「校验 → XOR → 按明文长度重帧」后交给 TLS 栈，并捕获
     serverRandom；握手后读方向：relay 方案帧跳过、链式 MAC 帧交付；
     写方向从首个载荷起链式 MAC（`"C"`）。
   - 证书：`allowInsecure=1` 跳过；否则 v2/v3 用新增 `CertPolicy::WebPki`
     （rustls-webpki 链 + 主机名 + CV 验签，webpki-roots 根集），v1 用 rustls 原生校验。
2. **SIP003 插件解析（`parse_ss`）**：`plugin=shadow-tls;password=…;version=…;
   host=…/sni=…;allowInsecure=1`（默认 version=3；名字 `shadow-tls`/`shadowtls`）；
   其余插件显式报错。`Outbound::Shadowsocks` 增 `shadowtls: Option<ShadowTlsConfig>`。
3. **组合面**：ss classic（含流密码）可挂插件；**ss2022 + 插件、UDP 均显式报错**
   （P31 边界，不静默）；`supports_udp` 对带插件的 ss 返回 false。
4. **ss 读写半泛化**：`SsReader/SsWriter` 内部改 `Box<dyn Read/Write + Send>` +
   `ShutdownFn`（半关闭回调），使同一 ss 数据路径可跑在 shadow-tls 帧层之上；
   直接拨号路径用 TcpStream 与 `shutdown(Write)` 回调保持不变。
5. **lab**：Go 夹具 `lab/proto-check/shadowtls-server`（直接复用 `sing-shadowtls`
   的 `Service`：v1/v2/v3、自签 TLS1.2/1.3 伪装站、认证成功后转发到 python ss 后端）
   + `shadowtls[-v2|-v1]-up` 与 `test-shadowtls{,-v2,-v1}`（交互 + 512KB +
   服务端 handler 交接日志 + ss 后端 target 日志）。
6. **附带修复（实质 bug）**：P24 的 Chrome 形状 ClientHello 两处不合规——
   `supported_versions` 列表长度误用 u16（ClientHello 应为 u8）、各处 GREASE 值
   独立随机导致偶发重复扩展类型。Go/OpenSSL 等严格解析器直接 alert
   （decode_error / protocol_version）；REALITY 服务端解析较宽松所以此前未暴露。
   本次改为 u8 长度 + uTLS 语义的**互异** GREASE 值，`tls13_real_server_handshake`
   由失败转为通过。

## 理由

- shadow-tls 的三版差异集中在「握手期改写 + 帧层 MAC」，把这两点封装在
  `shadowtls.rs` 后，ss 数据路径零改动即可复用（泛化读写半）。
- 证书策略默认严格（WebPKI）而不是默认跳过：v2/v3 的伪装站握手是真实 TLS
  会话，能验证就验证；`allowInsecure` 仅用于自签/测试场景。
- 严格解析器兼容性是「伪装质量」的一部分：CH 不合法会直接被目标站拒，
  主动探测风险上升；修复属于功能性收益而非仅测试通过。

## 后果

- 正面：`ss://…?plugin=shadow-tls;…` 可直接使用（v1/v2/v3）；与参考服务端
  跨实现互通；TLS 1.3 CH 在严格解析器（Go/OpenSSL/CDN）下的兼容性修复，
  同时覆盖 REALITY/Vision 路径。
- 负面/边界：v1 需伪装站支持 TLS 1.2（协议使然，参考实现同）；v2/v3 需 TLS 1.3
  伪装站（自实现栈只做 1.3）；插件仅 ss classic、仅 TCP；simple-obfs/
  v2ray-plugin 等其余 SIP003 插件未做（解析即报错）；v2 的票据甄别为本实现
  增强，与参考实现行为在极端时序下可能不同。
- 观测：lab 以服务端 handler 交接 + python ss 后端 target 日志 + 512KB 逐字节
  三方证据；状态面沿用 `relay.*`（未加专用计数）。

## 验证方式

- 单测：`cargo test` **232/232**——`shadowtls` 7 例（session_id MAC 零位、
  serverRandom 提取、v2 首帧前缀、v3 写链/读跳过 relay、V3HandshakeIo 反变换重帧、
  配置校验）；另有 `tls13_real_server_webpki`（真站 WebPKI 链+主机名+CV，忽略态）
  实测通过。
- lab：`shadowtls-up`/`test-shadowtls`（v3）、`-v2`、`-v1` 全 PASS
  （交互 + 512KB 逐字节 + `STLS handler conn` + `TCP target=` 三方交叉）。
- 回归：`verify` 9/9；`test-ss`（boxed 化后）、`test-ss2022`、`test-ssr` PASS。
- 真机：网关 down→up 自检 + `gateway.sh test`（出口 IP + DNS）+ 66 节点组 +
  0 panic；`tls13_real_server_handshake` 真站握手由失败转通过（CH 修复）。
- 文档：本 ADR + parity v2.8 + HTML v2.39 + NOTES §11.46 + README。
