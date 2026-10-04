# ADR-0049：P25 naive 出站——HTTP/2 CONNECT 隧道 + Basic 认证

- **状态**：已采纳（2026-10-04）
- **对应**：对标表缺口 #6 在 P24 后余项中的 naive
- **相关**：ADR-0047（P23 DoH h2，本次复用其帧层）、ADR-0042（HTTP CONNECT 出站）、
  NOTES §11.40；对照 naiveproxy 协议（HTTP/2 CONNECT + `Proxy-Authorization: Basic`）

## 背景

- P24 显式列出的边界里，`naive` 被标注为「独立协议栈（h2/h3 CONNECT）」暂缓。
- 但 P23 为 DoH 已实现一套最小 HTTP/2 客户端（`h2client.rs`：SETTINGS/PING/HEADERS+HPACK/
  DATA 流控/CONTINUATION/GOAWAY/RST、`tls::connect_alpn` ALPN 门控）——CONNECT 是 HTTP/2
  的本来用途，隧道所需的额外机制（响应侧收流、双向流控、DATA 帧透传）与 DoH 同源，
  属「可复用已有部件」的残项，而非新协议栈。
- naive 的主流形态即 `naive+https://`（h2 over TLS + Basic），H3 形态（`naive+quic://`）
  在真实订阅中占比低。

## 决策

1. **`h2client.rs` 抽帧层 + CONNECT 隧道**：
   - 抽出 `write_frame_raw` / `read_frame_raw`（`io::Result`）与 `strip_padding_io`，
     DoH 与 CONNECT 共用同一帧读写；`H2Conn` 增加 `next_stream`（响应侧新流分配）与
     对端 `SETTINGS_INITIAL_WINDOW_SIZE`（id=4）解析（`peer_initial_window`）。
   - `encode_connect_headers(authority, extra_headers)`：HPACK 编码 `:method`=CONNECT
     （静态名索引 2 + literal）、`:authority`（静态名索引 1），额外头（如
     `proxy-authorization`）用名字字面量；单测逐字节断言首字节。
   - `connect_tunnel()`：HEADERS(CONNECT，无 END_STREAM) → 等 `:status` 200 →
     返回 `(TunnelReader, TunnelWriter)` + reader 线程：解 DATA（入 `VecDeque` 并回
     `WINDOW_UPDATE`）/HEADERS/SETTINGS/PING/WINDOW_UPDATE（增发送窗口并唤醒写者）/
     RST/GOAWAY；写端双向流控（连接级+流级 `wait_window`）、`MAX_DATA_FRAME=16384`、
     `end_stream()` 幂等（发 END_STREAM，服务端才能读到 EOF 并回包）；两半都 drop 时
     shutdown 底层 TCP 唤醒 reader 线程。
2. **`outbound::Naive`**：URL 支持 `naive+https://` 与 `naive://`（userinfo 用
   `rsplit_once('@')` 兼容密码含 `@`）；`dial_tcp` 分支要求 `tls::connect_alpn` 协商出
   **h2**（否则报错退出，不降级 H1——CONNECT 隧道只在 h2 上有定义）；Basic =
   `base64(user:pass)`（有 user 才发头）；`server_addr()`/`name()` 纳入。
3. **显式边界（本轮不做，原因如实）**：
   - **H3/QUIC 形态（`naive+quic://`）**：URL 解析显式报「未实现」错误，不静默按 h2 处理；
     需 h3 CONNECT 流（现有 quinn 仅用于 DoQ/TUIC/hy2，未做 h3 帧层）；
   - **跨目标连接复用/连接池**：每个客户端 TCP 连接建独立底层 h2 连接（与 relay 模型一致）；
   - **服务端兼容性穷举**：只按 RFC 9113 CONNECT 语义实现，未对各家服务端做矩阵测试
     （lab 已过 Go 标准库 `net/http` h2 服务端跨实现）。

## 理由

- 复用 P23 最小 h2（零新依赖、零新协议栈），实现面集中在「CONNECT + 双向流控 + 半关闭」
  三件事，风险低；DoH 与 naive 共用帧层还能相互回归。
- CONNECT 隧道与 DoH 的差别只在「无 `:path`/`:scheme`、请求体即隧道载荷、响应体持续流」，
  在既有 `H2Conn` 上增量最小。
- Basic 走 TLS 内（`naive+https` 即 h2 over TLS），凭据以 base64 传输是 naive 协议自身
  的既定形态。

## 后果

- 正面：协议家族覆盖 ≈72% → **≈74%**、主流可用性 ≈96% → **≈97%**；真实订阅生态中
  naive 节点可直接使用，无需桥接；`h2client` 的帧层抽象同时服务 DoH 与 naive。
- 负面/边界：仅 h2（无 H3）；Basic 是 base64 明文语义，安全性依赖外层 TLS 且
  `insecure=1` 时存在 MITM 风险（与 HTTP CONNECT 出站同样的告诫，已在 URL 解析/文档标注）；
  每个客户端连接一条底层 h2 连接，不做连接池/多路复用；h2 隧道不可内核 offload
  （状态面按预期 `offloaded_total=0`，relay 直通）。

## 验证方式

- 单测：`h2client::connect_headers_encode`（HPACK 字节级）、`outbound::parse_naive_url`
  （两种 scheme、含 `@` 密码、空密码、sni 默认值）；`cargo test --release` **204/204**。
- lab：`naive-up` + `test-naive`（Go 标准库参考服务端，CONNECT 直挂 Handler + 上游 socket
  SO_MARK 防数据面二次接管 + 逐块 Flush）——交互零延迟（`RECV 0.00`）、512KB 逐字节、
  服务端日志 `proto=HTTP/2.0`、状态面 `offloaded_total=0`（h2 隧道不可内核拼接，符合预期）。
- 回归：`verify` 9/9；`test-sniff-punt` / `test-v6` / `test-doh-h2` / `test-dns-options` /
  `test-tuic` 均 PASS。
- 真机：新二进制重启网关启动自检通过、订阅组 66/66 alive、代理路径 generate_204 → 204、
  出口 IP 正常、日志 0 panic（期间订阅站出现一次 TLS 握手超时抖动，重试即过；与 P25 代码
  无关，属远端服务稳定性）。
- 文档：本 ADR + parity v2.3 + HTML v2.34 + NOTES §11.40。
