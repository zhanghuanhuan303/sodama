# ADR-0027：AnyTLS 客户端（真实订阅节点接入，P11）

- **状态**：已采纳（2026-10-04）
- **对应**：新增协议档位（第二份真实订阅的 18×anytls 节点）；附带 `--dial-timeout` 可配
- **相关**：ADR-0004（协议梯度）、ADR-0017、ADR-0026、NOTES §11.18、`lab/real-node-e2e.sh`

## 背景

第二份真实订阅（66 节点）中 18 个是 **AnyTLS**（anytls-go 协议，2024 起的新协议；
mihomo / sing-box 已支持）。ADR-0026 的普查把它列为边界外并给出 socks5 桥接过渡。
P11 的目标是让 mini-dae **原生**消费此类节点。

## 决策

1. 新增 `loader/src/anytls.rs`：anytls-go 协议 v2 的客户端子集——
   - 认证：`sha256(password) + padding0`（默认 scheme `0=30-30`）；
   - 帧：`[cmd 1B][sid BE32][len BE16][data]`；Settings/SYN/PSH/FIN 全支持；
     读路径处理 UpdatePaddingScheme（即时生效）/ServerSettings/SYNACK（错误上报）/
     HeartRequest（排队 HeartResponse）/Alert（作为错误上抛）；Waste 静默丢弃；
   - paddingScheme：默认值与 anytls-go **逐字节一致**（md5 `75cff2ad89aadf5e257059ee571ebe11`），
     实现 pkt 计数、区间随机与 `c` 检查符，首包批（Settings+SYN+PSH(目标)）计为 pkt 1；
2. URL：`anytls://password@host:port?sni=...&insecure=1`（密码在解析期即 SHA-256，
   协议认证只发摘要；TLS 固定开启）；
3. 边界（如实）：单 Stream——每次拨号一条 TLS + 一条 Stream，**无会话复用**；
   UDP（udp-over-tcp v2）不做（Outbound 层直连回退）；写方向半关闭直接 FIN TCP
   （单会话下与关闭连接等价）；不主动发心跳；
4. 附带小改动：`--dial-timeout <secs>`（默认 5s；`lab.sh` 用 `USE_DIAL_TIMEOUT` 透传）——
   真实节点慢首连（实测 >5s）会打满默认超时。

## 理由

- 协议基于 TLS + 简单帧，复用现有 `tls.rs`；padding 是唯一的"隐蔽性"核心，
  以 Go 参考逐行对齐并用 md5 钉死兼容；
- 证据分两级：本地 **sing-box 服务端**跨实现测试（可进 `cargo test`，缺 sing-box 自动跳过）
  + 真实订阅节点 e2e——避免自测自嗨；
- 单 Stream 子集对网关足够（每条客户端连接对应一条上游连接），复杂度显著更低。

## 后果

- 正面：原生消费 anytls 订阅；`cargo test` +7（89/89）；真实节点 e2e gstatic 204；
  `--dial-timeout` 对慢节点/桥接场景普适。
- 负面/代价：无会话复用（多连接场景每连接一次 TLS+认证，成本高于 anytls-go；
  实测 e2e 正常，后续可评估池化）；无 UDP；padding 为客户端单侧实现（服务端不校验具体长度）。
- 风险：若服务端未来强制校验 padding 长度，需要重新对拍；默认 scheme 硬编码，
  服务器下发 UpdatePaddingScheme 时即时更新（已验证）。

## 验证方式（实测）

- 单元/跨实现 7 项（+1 ignored 真实节点探针）：默认 scheme md5 对齐 Go、
  mock 服务端 framing/echo、Settings 内容（v=2/client/padding-md5）、
  UpdatePaddingScheme 作用于下一次写（定长 64 断言）、**sing-box anytls 服务端跨实现回环**；
- 真实节点（第二订阅 anytls 节点，`lab/real-node-e2e.sh` + `REAL_NODE_URL=anytls://…`）：
  client ns → tproxy → anytls → 真实节点 → gstatic **204**；relay up 1981B/down 4713B、
  dial_errors=0（`USE_DIAL_TIMEOUT=15`）；
- 回归：标准 verify 9/9；`cargo test --release` 89/89。

## 修订条件

需要会话复用、UDP（udp-over-tcp v2）或服务端强制 padding 校验时另写 ADR；
REALITY+Vision 仍属单独档位（见 ADR-0026 修订条件）。
