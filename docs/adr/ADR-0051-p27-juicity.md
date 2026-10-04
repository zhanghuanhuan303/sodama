# ADR-0051：P27 juicity v0 出站——QUIC + TUIC 式认证 + trojan 风格元数据

- **状态**：已采纳（2026-10-04）
- **对应**：对标表缺口 #6 在 P26 后余项中的 juicity
- **相关**：ADR-0018/0048（tuic v5、0-RTT）、NOTES §11.42；对照 olicesx/outbound
  `protocol/juicity/{client,stream_conn,stream_packet_conn}.go` 与
  `dialer/juicity/juicity.go`（链接解析）、e2e 服务端（lab 夹具由其移植）

## 背景

- juicity 是 dae 协议清单里的 QUIC 系代理（sing-box 亦有出站）：QUIC/TLS1.3 之上
  用与 TUIC 相同的 exporter 认证，再做 trojan 风格「网络字节 + 元数据」的数据流。
- P26 后剩余协议家族只有 ssr/juicity；juicity 所需部件（quinn、TLS exporter 认证、
  `Target` 的 SOCKS 风格编码）都已具备，属「已有部件组装」项。
- quic-go fork 在 `dae-work` 模块图内可离线构建，lab 可用独立 Go 服务端跨实现验收。

## 决策

1. **新模块 `juicity.rs`**（一个 dialer 复用一条 QUIC 连接，失效下次拨号重建）：
   - 认证（客户端单向流，50B，**保持打开**）：`[00][00][uuid16][token32]`，
     `token = TLS.ExportKeyingMaterial(label=uuid 裸字节, context=password)[32]`
     （与 tuic 同源；juicity 的服务端在同一条流上可继续接收 underlay 记录）；
   - TCP（每条连接一条双向流）：拨号即写 `[01][TYPE ADDR PORT]`，之后裸字节；
     `shutdown_write` = QUIC FIN（服务端据此半关闭真实 TCP）；
   - UDP（每条 NAT 会话一条双向流）：流首 `[03][目标元数据]`；每帧
     `[目标元数据][len u16][payload]`；回包 `[来源元数据]…`（读侧跳过来源）；
   - 元数据 = trojan 风格：`1`=IPv4(+4+2)、`4`=IPv6(+16+2)、`3`=域名(1+len+2)、
     `2`=命令；复用 `Target::encode_socks_addr_port`（编码一致）。
2. **链接**：`juicity://uuid:password@host:port?sni=…&allow_insecure=1`；
   uuid 严格校验（32 hex，无 UUID5 回退）；ALPN 固定 `h3`。
3. **lab 跨实现**：`lab/proto-check/juicity-server`（Go/quic-go fork，从上游 e2e 服务端
   移植为独立进程；协议常量就地从规范重述）+ `juicity-up`/`test-juicity`（TCP）与
   `juicity-udp-up`/`test-juicity-udp`（UDP 双工流帧）。
4. **显式边界（本轮不做，原因如实）**：
   - **full-cone underlay 模式**（`IV||PSK` 记录 + chacha20-poly1305 包加密的
     `TransportPacketConn`）：用于把整条 UDP underlay 映射到服务端；我们走
     stream-PacketConn 语义（每 NAT 会话一条流），与 dae 的默认 `udp` 路径一致；
   - 0-RTT、本地拥塞控制参数（`congestion_control`/`cwnd`/`cc_override` 忽略）、
     `pinned_certchain_sha256`（证书固定）。

## 理由

- 与 TUIC 共享「exporter 认证 + QUIC 连接复用」骨架，差异集中在数据流头与 UDP
  帧格式，实现与验证成本低于其协议家族名单里的地位。
- juicity 无 CONNECT 状态帧（目标不可达 = 流 reset），错误通过既有 relay 错误路径
  自然上报，无需新增状态机。

## 后果

- 正面：协议家族 ≈74% → **≈80%**、主流可用性 ≈97% → **≈98%**；QUIC 系再补一员。
- 负面/边界：如上第 4 条；另外服务端 UDP 回包来源元数据在回填前的行为按「忽略」
  处理（我们的 NAT 会话本就按目标键定会话）。

## 验证方式

- 单测：`juicity` 元数据布局（IPv4/域名逐字节）、认证头 50B 布局、
  `outbound::parse_juicity_url`（uuid/密码百分号解码/SNI/宽松校验）；`cargo test
  --release` **215/215**。
- lab：`test-juicity`（交互 + 512KB 双向 + 服务端 `JUICITY tcp target=…` 日志 +
  offloaded=0）；`test-juicity-udp`（`udp_probe` 3/3 + 服务端 UDP 会话 target 日志 +
  `sessions_proxied≥1`/`direct_fallback=0`）。
- 回归：`verify` 9/9；`test-tuic`/`test-hy2`（QUIC 系）与 `test-naive*` 全 PASS。
- 真机：新二进制重启网关自检通过、组 66/66、generate_204 → 204、0 panic。
- 文档：本 ADR + parity v2.5 + HTML v2.36 + NOTES §11.42。
