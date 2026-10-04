# ADR-0017：P5 G2 范围与边界——vless（TCP/UDP）与 vmess（AEAD，alterId=0）

- **状态**：已采纳（2026-10-03）
- **对应**：ADR-0009 的 P5（协议栈）；ADR-0004 的「Dialer 梯度」第二梯
- **相关**：ADR-0016（G1：ss/trojan；协议/offload 互斥与跨实现验收口径由本 ADR 延续）、ADR-0015（relay/UDP NAT 基座）

## 背景

G1 落地了 ss/trojan 与跨实现验收。G2 继续梯度，补齐 dae 生态里最常用的 v2ray 系协议：

1. **vless**：wire 极简（明文头 + 可选 TLS），但 `flow`/`type` 分叉多（vision/XUDP、ws/grpc/reality），
   必须显式划定子集而不是"解析了就当支持"；
2. **vmess**：AEAD 变体（alterId=0）涉及多层密钥派生（嵌套 HMAC KDF、AES-ECB auth id、
   AES-GCM 请求头、SHAKE128 长度掩码/填充、chunk 分块与终止块），任何一处字节级偏差都会
   变成"自测能过、生态不通"——因此 G2 的验收必须包含**真实 Go 客户端**（dae 实际依赖的
   `olicesx/outbound` fork）对打我们独立实现的 Python 服务端；
3. UDP 侧：vless/vmess 的 UDP 是 **over stream**（TCP/TLS 上的帧/块），与 G1 的 ss UDP
   （独立 UDP socket）不同，需要扩展 `UdpRelay` 的抽象；
4. 会话建立的线程语义：UDP NAT 会话首包要在 `dns_loop` 线程里拨号。G1 的 ss/direct 拨号是
   微秒级所以看不出来，G2 的 TLS 拨号是一个 RTT 级操作——不能继续拿着会话表锁拨号。

## 决策

1. **vless（G2a）**：`--dialer vless://uuid@host:port?...`
   - 子集：`type=tcp`、`headerType=none`、`security ∈ {none,tls}`、`encryption=none`；
     `flow` 非空（vision/XUDP）、`security=reality`、`type ∈ {ws,grpc,h2,kcp,…}` 一律**硬失败**；
   - UUID：标准 8-4-4-4-12（带/不带横线、大小写均可）；长度 ∉[32,36] 时按 Xray 兼容行为做
     UUID5 派生（`SHA1(16×0x00‖password)`，置 version5/variant）；
   - wire：请求 `[ver=0][uuid16][addonLen][addons][cmd=1|2][port BE16][ATYP+ADDR][payload]`；
     响应 `[ver=0][addonLen][addons]` **惰性解析**（首次 read/recv 时消费）；cmd=3（mux）拒绝；
   - UDP：同一 TCP/TLS 流上双向 `[len BE16][payload]`（一数据报一帧，0 长度合法），
     目标固定为连接建立时的地址（无 per-frame 地址，多目标 XUDP 不做）。
2. **vmess（G2b）**：`--dialer vmess://base64(JSON)`（v2rayN 分享格式）
   - 子集：`aid=0`（只做 AEAD）、`net=tcp`、`type=none`、`scy ∈ {auto,aes-128-gcm,chacha20-poly1305}`；
     `aid≠0`、`scy ∈ {none,zero}`、`net/type` 其它值、`flow/pbk/sid/spx/fp` 非空、legacy 文本链接
     一律**硬失败**；`tls ∈ {none,tls}` 可选，`sni` 支持、`allowInsecure` 支持（bool）；
   - 请求头：`eAuthID(16) ‖ AES-GCM(BE16(L_instr), aad=eAuthID)(18) ‖ connNonce(8) ‖ AES-GCM(instr)(L+16)`；
     `eAuthID = AES-128-ECB(KDF(cmdKey,"AES Auth ID Encryption")[:16],
     BE64(unix)‖rand4‖BE32(crc32(前 12B)))`；`cmdKey = MD5(uuid16‖"c48619fe-…")`；
   - KDF 为**嵌套 HMAC-SHA256**（最内层密钥 `"VMess AEAD KDF"`，每层以上一层 HMAC 实例为
     hash 函数、该层 path 为密钥；不是朴素迭代）——已与独立 Python 实现逐字节对齐；
   - instruction：`[1][bodyIV16][bodyKey16][V][options=0x0D][P<<4|security][0][cmd][port BE16][ATYP+ADDR][P 随机][FNV-1a32]`；
   - 响应头：`respKey=SHA256(bodyKey)[:16]`、`respIV=SHA256(bodyIV)[:16]`，两段 AES-GCM
     （长度块 + `[V,0,0,0]`），客户端校验 V 与 cmd=0；长度上限 1024（防御性，标准为 4）；
   - 数据块：`BE16(size XOR mask) ‖ AEAD(payload) ‖ padding`，`size = payload+16+padding`；
     SHAKE128(dirIV) **先抽 padding（%64）、再抽 mask**；nonce `BE16(counter)‖dirIV[2:12]`；
     终止块 `size == 16+padding`（TCP 半关闭信号；UDP 不使用）；单块明文上限 16302；
     chacha 会话密钥 = `md5(k)‖md5(md5(k))` 扩成 32B；请求头 AEAD 恒为 AES-128-GCM；
   - UDP：固定目标模式（cmd=2），**一个数据报一个块**，不做 packetaddr（多目标魔串）。
3. **共享 TLS 层**：把 G1 在 `trojan.rs` 里验证过的 rustls 读路径（含 16KB 明文缓冲不变量与
   pending 密文缓冲）抽成 `tls.rs`，trojan/vless/vmess 共用；支持 ALPN（链接 `alpn=` 时按
   配置缓存 ClientConfig）。G1 的 trojan 行为不变（回归已证）。
4. **UDP over stream 的会话抽象**：`UdpRelay` 新增 `Stream` 形态（Mutex 读/写两半 +
   底层 TcpStream 用于 `SO_RCVTIMEO`）；vless/vmess 的 UDP 帧解析器带**pending 缓冲**，
   超时/短读不丢半帧进度，空闲读超时（2s）只用于会话存活检查。
5. **拨号不再持锁**：`udp_nat_handle` 重排为「快路径持锁查表 / 慢路径锁外拨号 / 插入时防御性
   去重」。G1 的 ss/direct 拨号快到掩盖了原实现（拨号在 NAT 表锁内），TLS 拨号不允许这样。
   **遗留边界**：新会话首包仍在 `dns_loop` 线程同步拨号（dae 用 goroutine）；对循环里的
   DNS 与其它 UDP 会话是一段 RTT 级停顿，sodama 明确记为待改项，不假装已异步。
6. **能力与互斥**：vless/vmess `supports_offload()==false`（帧式封装不交内核拼接，
   `--offload` 时 `offloaded_total` 必须为 0）；`supports_udp()==true`（G2 起 ss/vless/vmess）。
7. **验收口径（三方交叉）**：
   - Rust 客户端 ↔ 独立 Python 服务端（`lab/vless_server.py` / `lab/vmess_server.py`）：
     TCP 512KB 逐字节一致、UDP 3/3、服务端日志见目标、offload 互斥、`dial_errors=0`；
   - **真实 Go 客户端**（parity 的 `dae-work` 里用 `olicesx/outbound` 的 v2ray dialer）↔
     同一 Python 服务端：TCP/UDP echo 通过（`lab/proto-check/run.sh`）；
   - 本地 Rust↔Python 单测（`vless.rs::udp_roundtrip_against_python_server`）把协议问题从
     拓扑问题里剥离；`cargo test` 46/46。

## 理由

- vless/vmess 的 wire 规格直接从 dae 的实际依赖（`olicesx/outbound`）读出来，并把关键常量
  （KDF 路径串、盐、options/chunk 语义）在 ADR 里固定，避免以后"照文档重写"引入漂移；
- 「Python 服务端 ↔ Rust 客户端 ↔ Go 客户端」三方交叉能识别**双方同错**：如果只做
  Rust↔Python 对测，KDF/掩码这类对称性错误会一起错过去；Go 客户端是 dae 生产路径，
  它认了才算生态兼容；
- 16KB rustls 明文缓冲、connected-UDP 回包过滤这两个坑都会以"现象诡异、日志无用"的形式
  出现（512KB 拆连接 / UDP 永久超时），写进本 ADR 与 NOTES 以免重踩。

## 后果

- 正面：`--dialer` 梯度到 `direct|socks5|ss|trojan|vless|vmess`；UDP 代理从 1 个协议扩到 3 个；
  TLS 层复用让后续 QUIC 以外协议（如 more tls-based）直接可用；UDP NAT 拨号不再持锁；
  状态面 `dialer` 回显归一化名字（`vless://host?security=…` / `vmess://host?scy=…`）。
- 负面/代价：vmess UDP 每会话一条 TCP/TLS 流（队头阻塞：同一会话的多个数据报共享一个流，
  2s 读超时只是存活检查）；新会话首包同步拨号（见决策 5 边界）；vmess 无 aid≠0/CFB、
  无 packetaddr；vless 无 vision/XUDP/reality；无 uTLS 指纹（`fp` 拒绝）。
- 风险：Go 客户端链接解析有两个已知偏差（vless 的 `allowInsecure` 被忽略、vmess 的 `scy`
  被忽略恒用 aes-128-gcm）——我们的 proto-check 因此只对 vless 做明文、对 vmess 做
  none/tls+aes；Rust 侧的 chacha 与 TLS 变体由 lab e2e 覆盖。若上游修正这些偏差，
  proto-check 可直接加 case。

## 验证方式（实测）

- `cargo test --release`：46/46（新增 vless UUID/请求头/UDP 帧解析、vmess KDF 参考向量、
  auth id CRC、chunk 回环与逐字节分片、UDP 数据报回环、vless↔Python 服务端 UDP 回环）。
- `lab.sh vless-up && test-vless`：`stream-ok bytes=524288`；`vless tcp: conns=2
  bytes_up=524299 bytes_down=524333 offloaded=0`；服务端日志 `TCP target=1.1.1.1:8080`。
- `lab.sh vless-tls-up && test-vless`：同上（security=tls + 自签 + allowInsecure）。
- `lab.sh vless-udp-up && test-vless-udp`：`summary=3/3`、`sessions=1/1 proxied=1 fallback=0`、
  服务端日志 `UDP target=2.2.2.2:9998`。
- `lab.sh vmess-up && test-vmess`（chacha20-poly1305）与 `vmess-tls-up && test-vmess`
  （aes-128-gcm + TLS）：均 `stream-ok bytes=524288`、`offloaded=0`、`dial_errors=0`。
- `lab.sh vmess-udp-up && test-vmess-udp`：`summary=3/3`、`proxied=1 fallback=0`。
- `lab/proto-check/run.sh vless`、`lab/proto-check/run.sh vmess`、`lab/proto-check/run.sh vmess tls`：
  真实 Go 客户端 TCP+UDP echo 全过（`PROTO-CHECK …: PASS`）；`vless tls` 因 Go 链接层忽略
  `allowInsecure` 报 x509（预期，见"风险"）。
- 回归：标准/单臂 verify 9/9；DNS 六专项；`test-relay`/`test-relay-idle`/`test-relay-offload`/
  `test-udp-relay`/`test-udp-idle`；`test-ss`/`test-trojan`/`test-ss-udp`；`test-config`/
  `test-status`/`test-forward`；`lab/parity.sh` 逐字节一致。

## 修订条件

G3（QUIC 系 hysteria2/tuic）新写 ADR；若要 vision/XUDP、packetaddr、aid≠0、scy=none 或
协议感知 offload，另写 ADR 取代本 ADR 对应子条；UDP 会话首包异步化（去 dns_loop 停顿）
落地时修订决策 5 的边界描述。
