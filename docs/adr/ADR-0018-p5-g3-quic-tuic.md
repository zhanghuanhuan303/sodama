# ADR-0018：P5 G3 范围与边界——tuic v5（QUIC）落地；hysteria2 归 G3b

- **状态**：已采纳（2026-10-03）
- **对应**：ADR-0009 的 P5（协议栈）；ADR-0004 的协议梯度第三梯（QUIC 系）
- **相关**：ADR-0016/0017（G1/G2 的验收口径：独立对端 + 协议/offload 互斥）、ADR-0003（用户态运行时）

## 背景

G3 是协议梯度的 QUIC 系（tuic / hysteria2）。开工前的侦察结论决定了范围划分：

1. **Rust 侧可离线构建**：本机 cargo 缓存已有 `quinn 0.11.12`、`tokio 1.53`、`tokio-rustls`
   与 `bytes`，但**没有** `rustls-platform-verifier`（quinn 默认特性之一）→ quinn 必须
   `default-features=false` + 显式 `runtime-tokio`/`rustls-ring`；
2. **Python 无 QUIC 栈**（无 `aioquic`，pip 不可假定）→ G1/G2 的「独立 Python 服务端」模式
   不可沿用；改用 **Go + quic-go 独立参考服务端**（quic-go 与 outbound 都在 dae 的 module
   缓存里，`lab/proto-check/tuic-server` 按规格独立实现，不复用 outbound 代码）；
3. **hysteria2 的工作量结构与 tuic 不同**：认证是标准 HTTP/3 请求（**解码侧必须实现 HPACK
   Huffman** 才能读 `:status 233` 与响应头）、拥塞控制 Brutal（quinn 的 `Controller` trait
   只有窗口/事件粒度，只能近似）、salamander 混淆（要在 `quinn::AsyncUdpSocket` 层按
   GSO 段逐段 XOR）→ 单轮内与 tuic 并行做两套会导致两边都不扎实。

因此 G3 拆为 **G3a（本 ADR 落地）：tuic v5 TCP+UDP**；**G3b（同 ADR 定义范围与路径）：
hysteria2**。

## 决策

1. **异步运行时（新增架构件）**：引入 tokio（多线程、2 worker、惰性全局 `Runtime`）+ quinn
   （见背景 1 的特性裁剪）。阻塞 relay 线程通过 `Runtime::block_on` 桥接 QUIC 的 IO
   （endpoint driver 跑在 runtime worker 上）；`tls.rs` 的 rustls 配置构造（NoVerify/webpki
   根 + ALPN）抽为共用函数，QUIC 与 TCP 协议共用同一套证书校验语义。
2. **tuic v5 子集（对照 `protocol/tuic`，规格见 `docs/modules/tuic-v5-client-spec.md`）**：
   - 认证：客户端单向流 `[05][00][uuid16][token32]` 后 FIN；`token = TLS 1.3 exporter`
     （label = uuid 16 裸字节，context = password），**不是** sha256(password)；认证无响应，
     失败表现为连接被 `0xfffffff1` 关闭；
   - TCP：每条 relay 连接一条双向流 `[05][01][ATYP+ADDR+PORT]` 后裸字节；半关闭 = QUIC FIN；
     目标不可达 = 服务端 CancelRead/CancelWrite（无状态帧）；
   - UDP：QUIC DATAGRAM（native 模式）`[05][02][assoc u16][pkt u16][frag_total u8][frag_id u8][size u16][ADDR|0xff][data]`；
     超 `max_datagram_size()` 时分片（单片上限 1452，首片带地址、后续 `0xff`）；接收侧按
     PKT_ID 重组（同一时刻一个候选，30s 过期）；`Dissociate` 不来不发、心跳收到忽略；
   - 连接策略：**一个 dialer 复用一条 QUIC 连接**（懒建；`close_reason()` 非空时下次拨号重建）；
     `udp_relay_mode=quic`、0-RTT、连接迁移、退休宽限均不做（边界）；
   - ALPN 缺省 `h3`（生态惯例），链接 `alpn=` 可覆盖；`congestion_control`/`cc_override`/`cwnd`
     是本地 CC 选择、无线上语义，接受但忽略（quinn 自带 CC）。
3. **SO_MARK 与 QUIC**：quinn 自建 socket 无法打标，改用 `Endpoint::new` 传入我们自己
   `bind + SO_MARK` 的 `UdpSocket`（否则 lab 里 QUIC 上游会被数据面二次捕获）。
   三处 socket 创建（Rust 客户端、Go 参考服务端、G1/G2 的 Python 服务端）对非 root 统一
   **降级为告警**（cargo test / 非 root 环境无数据面、无自环风险；lab 以 root 运行）。
4. **接口适配**：`DialedStream.socket` 与 `RelayHandle.upstream` 改为 `Option<TcpStream>`
   （QUIC 没有底层 TCP；offload 仍只对 direct/socks5 开启，语义不变）。
5. **验收口径**：
   - 本地跨实现单测：Rust/quinn 客户端 ↔ Go/quic-go 参考服务端（TCP 256KB 往返 + FIN 透传；
     UDP 小包 + 3000B 强制分片往返）；
   - lab e2e：`tuic-up && test-tuic`（512KB 逐字节一致、`offloaded=0`、`dial_errors=0`、
     服务端日志 `TCP target=1.1.1.1:8080`）；`tuic-udp-up && test-tuic-udp`（3/3、
     `proxied>=1 fallback==0`、服务端日志 `UDP target=2.2.2.2:9998`）；
   - 回归：原有九用例 × 两拓扑、DNS 六专项、relay/offload/UDP、G1/G2 协议专项、`parity.sh`。
6. **G3b（hysteria2，下一步执行）范围**：
   - QUIC：ALPN `h3`、TLS1.3、`EnableDatagrams` 等价配置；keepalive 5s / idle 60s；
   - 认证：手写最小 HTTP/3 —— 一条双向流发 HEADERS 帧（`0x1 | len | QPACK`）+ FIN；
     QPACK 编码可用「前缀 `00 00` + 静态表索引（`:method POST`=20、`:scheme https`=23）+
     name-ref（`:authority`=0、`:path`=1）+ literal（`Hysteria-Auth`/`Hysteria-CC-RX`/
     `Hysteria-Padding`），**不做 Huffman 编码**；解码必须实现 HPACK Huffman（quic-go 侧
     总是 Huffman 编码 literal），可引入 `hpack`/`httlib-huffman` 类 crate（crates.io 可达）
     或自带 256 项表；校验 `:status == 233`，读 `Hysteria-UDP` / `Hysteria-CC-RX`；
   - TCP：双向流首帧 `0x401 (varint 44 01) | addr_len | addr("host:port") | pad_len | padding`，
     之后裸字节；服务端应答 `status|msg_len|msg|pad_len|padding`；半关闭 FIN/STOP_SENDING；
   - UDP：QUIC DATAGRAM `[SessionID u32][PacketID u16][FragID u8][FragCount u8][addr_len varint][addr][data]`，
     分片/重组按 `internal/frag`；
   - 拥塞控制：先跑 quinn 自带 BBR/Cubic（互通无关）；Brutal 若做，用
     `TransportConfig::congestion_controller_factory` 近似移植（pacer 与 ackRate 粒度受限，
     在 ADR 中如实标注「近似」）；
   - 混淆：salamander 后置（`AsyncUdpSocket` 包装 + GSO 段处理），首版按「无 obfs」验收；
   - 验收：Go http3 参考服务端（同 tuic 模式，独立实现 /auth + 代理帧）↔ Rust 客户端。

## 理由

- QUIC 系的第一性差异不是「多一个协议」而是「多一个运行时」：把 tokio/quinn 的引入、
  连接复用策略与桥接方式一次性定清楚，hysteria2 只需在同一个 QUIC 运行时上加协议层；
- 参考对端从 Python 换成 Go/quic-go 是环境约束下的最诚实选择：quic-go 是 dae 实际依赖的
  QUIC 实现，独立写的参考服务端能覆盖「认证/流/分片」全部关键路径，且能跑在 lab 的
  root/host-ns 语义里（SO_MARK）；
- 把 hysteria2 拆出去而不是硬塞，是因为它的三块（h3+HPACK、Brutal、salamander）各自都能
  单独失败；G3a 交付「QUIC 运行时 + 一条完整 QUIC 协议」更能保证质量。

## 后果

- 正面：`--dialer` 梯度到 `…|tuic://`；QUIC 运行时/tokio 桥接/流与 datagram 抽象就位，
  hysteria2 可复用；`DialedStream`/`RelayHandle` 的「无底层 TCP」语义显式化；状态面
  `dialer` 回显 `tuic://host:port`。
- 负面/代价：多两个依赖面（tokio/quinn，锁定本地缓存版本特性）；一个 dialer 一条 QUIC 连接
  但**无重连状态机**（fail 后下次拨号重建，不做 10s 退休宽限）；UDP 会话各占一个 ASSOC_ID
  但共享连接（若连接被服务端关闭，所有会话一起失效）；ALPN 缺省 `h3` 是**惯例推断**而非
  源码默认（可覆盖）。
- 风险：QUIC 路径的 MTU/分片预算随路径变化（客户端用 `max_datagram_size()` 动态取值，不
  硬编码）；Go 参考服务端与 quinn 的 datagram 能力协商（`max_datagram_frame_size`）必须
  双向显式启用，否则回包方向直接报错（实测踩过）。

## 验证方式（实测）

- `cargo test --release`：53/53（新增 tuic 帧编解码/非法帧/重组顺序与丢弃、TCP 大流量跨实现、
  UDP 小包 + 3000B 分片跨实现）。
- `lab.sh tuic-up && test-tuic`：`stream-ok bytes=524288`；`tuic tcp: conns=2
  bytes_up=524299 bytes_down=524333 offloaded=0`；Go 服务端日志 `TCP target=1.1.1.1:8080`。
- `lab.sh tuic-udp-up && test-tuic-udp`：`summary=3/3`；`tuic udp: sessions=1/1 proxied=1
  fallback=0`；服务端日志 `UDP target=2.2.2.2:9998`。
- 本地跨实现单测：`tuic::tests::{tcp,udp}_roundtrip_against_go_server` 通过（TCP 256KB +
  FIN 透传；UDP 小包 + 3000B 分片往返，服务端按 `MaxDataLen` 回包分片）。
- 回归：标准/单臂 verify 9/9；G1（ss/trojan/ss-udp）与 G2（vless/trojan 等 UDP 专项）全过；
  `test-relay`/`test-relay-offload`/`test-udp-relay` 全过（`Option<TcpStream>` 改动无回归）；
  `lab/parity.sh` 逐字节一致。

## 修订条件

G3b（hysteria2）落地时新写 ADR（或在本 ADR 上追加「已执行」章节并互链）；若要 0-RTT、连接
迁移、`udp_relay_mode=quic`、TUIC 退休宽限/重连状态机或 Brutal 保真移植，另写 ADR 取代对应
子条；若 quinn 后续把 datagram 能力协商/自定义 socket 的 mark 支持做得更直接，可简化决策 3。
