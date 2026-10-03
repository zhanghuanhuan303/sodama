# ADR-0020：P5 G3b+ 执行——hysteria2 的 salamander 混淆、Brutal 近似与 udphop

- **状态**：已采纳（2026-10-03）
- **对应**：ADR-0019 的「修订条件」三项（salamander / Brutal / udphop）
- **相关**：ADR-0018（QUIC 运行时与连接复用）、ADR-0019（G3b 落地与如实边界）

## 背景

ADR-0019 落地 hysteria2 时明确三项不做：salamander 混淆、Brutal CC、udphop。本轮按该 ADR 的修订条件执行。
实现前从 Go 侧核对的关键事实：

1. **salamander**（Go `protocol/hysteria2/obfs`）：
   wire = `[8B 随机 salt][payload XOR key]`，`key = BLAKE2b-256(PSK || salt)`，keystream 以 32B 循环；
   PSK ≥ 4B；收侧 ≤ 8B 的包直接丢弃。Go 的 `net.PacketConn` 包装不是 OOBCapable → quic-go 退回
   非 GSO 路径（每包一次写）。
2. **Brutal**（Go `client/congestion.go` + `protocol/tuic/congestion.UseBrutal`）：认证成功后按
   `min(server_rx, client_tx)` 装**固定速率**发送器；`cc_override` allowlist = `bbr`/`brutal`/`bbr3`
   （`cubic`/`new_reno` 显式拒绝）；空 override 且服务端回 `hysteria-cc-rx: auto` 时走探测式 CC（默认 bbr3），
   否则带宽目标 > 0 即选 Brutal。
3. **udphop**（Go `protocol/hysteria2/udphop`）：目标端口并集（`,` / `-` / `all`，Normalize 排序合并）；
   每 interval（**最小 5s**）随机换一个目标端口 + 新的本地 socket（新四元组），旧 socket 保留一个 interval
   做宽限；对 QUIC 层**谎报逻辑地址**；服务端侧靠 quic-go fork 的 “Hysteria connection migration”
   （每个有效包都 `SetRemoteAddr`，无需配置）。dae 把 hop interval 放在**全局配置** `udphop_interval`
   （默认 30s），链接语法里没有这一项。
4. **quinn 0.11 侧的三条硬约束**（决定了实现形态）：
   - `Controller` 只有窗口/ack/丢包事件粒度，没有 pacer 直接控制权；pacer 是 token bucket，容量按
     `window × 5/4` 与 RTT 推导；
   - 客户端对「migration-initiating packet」（来源地址变化）直接丢弃 → hop socket 必须对 quinn
     恒定谎报逻辑服务器地址；
   - Endpoint driver 在 `poll_recv` 返回 Pending 后只等**已注册的 waker**：新增 socket 若不主动唤醒，
     driver 不会再去 `poll_recv`（旧 socket 无数据 ⇒ 死等）——这是本轮最贵的实现坑。

## 决策

1. **salamander**：`quicsock::ObfsSocket`（`AsyncUdpSocket` 包装），逐 datagram 加盐 XOR；
   BLAKE2b-256 用 `blake2 0.10`（首个新增密码学依赖，已在本地缓存）；PSK < 4B 拒绝；
   `obfs=salamander` 缺 `obfs-password` 报错；`obfs=gecko` 明确不做（配置期报错）。
   用 Go 生成的 `BLAKE2b-256(PSK||salt)` key 向量做跨实现单测。
2. **Brutal 近似**（`brutal.rs`，HybridController）：
   - inner 固定 quinn BBR（近似 Go 默认 bbr3 的探测行为）；
   - 认证后按 Go `resolveCongestion` 语义算目标：`auto` → 0；`brutal`/空 override →
     `min(server_rx, client_tx)`（server_rx 取响应头 `hysteria-cc-rx`，`auto` 视为 0）；
   - 目标 > 0 时 `window = max(2×mtu, rate × srtt)`，丢包事件**不收缩** Brutal 窗口；
   - **如实标注近似**：quinn 的 pacer 由窗口推导，实际发送速率约放大 25%（窗口→速率换算）；
   - `cc_override`：`bbr` → BBR；`brutal` → 上述；`bbr3` → 用 BBR v1 近似；`cubic`/`new_reno`
     按 Go 侧同样显式拒绝（不静默降级）。
3. **udphop**（`quicsock::HopSocket`）：
   - 端口并集解析与 Go `ParsePortUnion` 同语义（含 `all`/`*` 展开、排序合并）；
   - 每 interval 随机换目标端口 + 新本地 socket（best-effort SO_MARK），旧 socket 宽限一个 interval；
   - 对 quinn 谎报逻辑地址（`meta.addr` 恒为 dial 地址）；
   - **新增 socket 后主动唤醒保存的 recv waker**，让 endpoint driver 重新对全部 socket 注册；
   - interval：链接扩展 `udphop-interval=<秒>`（默认 30，最小 5，与 Go 下限一致）——dae 把该值放在
     全局配置，链接语法没有对应项，此为 mini-dae 扩展；
   - 服务端：hy2-server 增加 `-hop-ports`（多 socket mux：从任意 socket 收，回复走「该客户端最后一次
     来包的 socket」）；quic-go fork 的服务端迁移不需要额外配置。
4. **链接解析**：`obfs=salamander&obfs-password=…`、`cc_override=bbr|brutal|bbr3`、
   端口并集（`443,8443-8450` / `all`）自动进入 hop 模式。
5. **验收口径**：cargo 跨实现 3 项（obfs TCP+UDP、Brutal 路径 256KB、hop 11s 跨 2 跳）+ lab 4 会话
   （`hy2-obfs-up`/`hy2-obfs-udp-up`/`hy2-brutal-up`/`hy2-hop-up`，含服务端日志证据）。

## 理由

- 三项能力各自独立可败，但共用同一个 socket 中间件层：把「混淆 / 跳端口 / 转发」分成可组合的
  `AsyncUdpSocket` 包装（quinn → Obfs → Hop → Plain），每层都能单独单测，也能单独跨实现验收；
- Brutal 用「速率目标句柄 + hybrid controller」而不是每次认证明重建连接：quinn 的控制器在连接建立时
  固定，认证后才知道 server_rx，共享 `Arc<AtomicU64>` 是唯一不改 quinn 内部的做法；
- hop 方案选择「对 quinn 说谎 + 主动唤醒」而不是改 quinn：改动面最小，且与 Go 的
  «fake addr + 自管 PacketConn» 思路一致；服务端迁移由 quic-go fork 现成支持。

## 后果

- 正面：hysteria2 三项补齐并对齐 Go 的链接语义；`quicsock` 中间件可复用于后续 QUIC 协议；
  `cc_override` 的错误值在解析期就报错（同 Go）。
- 负面/代价：Brutal 是**近似**（25% pacer 余量、无 ackRate 反馈）；obfs/hop 下 GSO/GRO 关闭
  （每包一次 sendmsg，与 Go 包装后一致）；`udphop-interval` 是链接扩展（与 dae 的全局配置形态不同）；
  gecko 不做。
- 风险：hop 间隔过密会因服务端地址反复回退而失速（实测 300ms 会卡死；Go 侧同样强制 ≥5s，
  故视为超范围配置）；服务端必须接受 QUIC 迁移（真实 hysteria2 与 fork 均接受）。

## 验证方式（实测）

- `cargo test --release`：73/73（新增 9 项：端口并集、salamander 回环、Go key 向量、hop 旋转+回程、
  Brutal 窗口数学、hybrid 切换、obfs/Brutal/hop 三项跨实现）。
- 跨实现：Rust/quinn ↔ Go/http3 参考服务端——obfs（TCP 64KB + UDP 3000B 分片）、
  Brutal（`cc_override=brutal` + upmbps 2MB/s，256KB×2）、hop（`-hop-ports` mux，11s 跨 2 跳）。
- lab：`hy2-obfs-up && test-hy2-obfs`（512KB，服务端日志 `salamander obfs enabled`）；
  `hy2-obfs-udp-up && test-hy2-obfs-udp`（3/3）；`hy2-brutal-up && test-hy2-brutal`（512KB）；
  `hy2-hop-up && test-hy2-hop`（两轮 512KB 跨 5s 跳端口，`udphop mux` 证据）。
- 回归：标准/单臂 verify 9/9、DNS 六专项、relay/offload/UDP 五专项、G1/G2/G3a 专项、
  `lab/parity.sh`、`lab/proto-check`。

## 修订条件

若 quinn 暴露 pacer 直接控制（或实现 bbr3），把 Brutal 从近似升级为保真、bbr3 换成真实现，另写 ADR 取代
本 ADR 第 2 条；若要 obfs/hop 下恢复 GSO（按段处理混淆）或支持 dae 全局 `udphop_interval` 语义，
另写 ADR 细化对应子条。
