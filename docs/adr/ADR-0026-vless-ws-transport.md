# ADR-0026：VLESS WebSocket 传输（真实订阅节点接入）

- **状态**：已采纳（2026-10-04）
- **对应**：扩展 ADR-0017 的 vless 传输边界（`type=tcp` → `tcp/ws`）；P10 执行
- **相关**：ADR-0004（协议梯度）、ADR-0017、NOTES §11.17、`lab/real-node-e2e.sh`

## 背景

P5-G2 的 vless 只做 `type=tcp`（ADR-0017 边界）。拿真实订阅（50 节点）验证时发现：
市面主流 vless 节点是 **WS + TLS + CDN** 形态（CF 优选：`host`/`sni`/`path` 参数 +
443/8443/2053/2083/2087/2096 端口），现有客户端在解析期直接拒绝 `type=ws`——
无法消费真实订阅，是"接入原有生态"的关键缺口。

## 决策

1. 新增 `loader/src/ws.rs`：RFC6455 客户端传输层（HTTP Upgrade 握手 + 掩码二进制帧），
   支持拆半：
   - 读半：`remaining` 计数 + 直接读进调用方缓冲（不缓存整帧），续帧当字节流，
     ping → 排队 pong，close → EOF；
   - 写半：每次 `write` 发一帧（掩码、FIN=1），pong 队列在写/flush 时顺带发出。
2. `vless://` 解析接受 `type=ws` 与 `host`/`path` 参数（`host` 缺省=sni，`path` 缺省=`/`）；
   `Outbound::Vless` 增加 `transport: Tcp | Ws { host, path }`。
3. ws 与 tcp 共用现有 TLS/拨号/relay 路径；UDP over stream 的 vless 帧套在 ws 帧内（帧中帧）。
4. 边界（仍显式拒绝/不做）：grpc/h2/kcp/httpupgrade；`fp`（uTLS 指纹）忽略（rustls 无 uTLS）；
   permessage-deflate；ws close 不做半关闭（直接 FIN，与 TLS 层一致）。

## 理由

- WS 是字节流封装，插入点清晰（TLS 半与 vless 帧之间），不动现有分层；
- 先以参照客户端（v2ray）建立真实节点基线，再逐目标对我们的实现对拍，
  可把"目标本身被节点黑洞"与"实现 bug"区分开（本次实测确实遇到前者）；
- 订阅凭证不入仓库：e2e 走环境变量 + `/tmp` 规则文件；仓库内只保留 env 驱动的
  ignored 探针与通用脚本。

## 后果

- 正面：sodama 可消费真实 vless-ws 订阅并端到端出网（204 实测）；协议栈首次接入
  商用节点生态；UDP-over-ws 同样可用。
- 负面/代价：无 uTLS 指纹（对强指纹校验的 CDN 可能受限）；不做 permessage-deflate；
  pong 仅在写路径顺带发出（只读流量下 ping 应答延迟——实测 CF 节点不主动 ping）；
  ws 传输不参与 offload（与 vless 既有约束一致）。
- 风险：目标可达性受节点策略影响（实测部分目标被节点黑洞，参照客户端同样失败）。

## 验证方式（实测）

- 单元：ws 帧/掩码/续帧/ping/握手回环 4 项；URL 解析（ws 参数/缺省/grpc 拒绝）3 项；
  `cargo test --release` **80/80**（+1 ignored 探针）。
- 真实节点（50×vless-ws 订阅）：
  - 拨号探针 `real_vless_ws_probe`（env 注入，`#[ignore]`）：经节点取回真实 HTTP 响应；
  - 网关 e2e `lab/real-node-e2e.sh`：client ns → tproxy → vless-ws → 真实节点 →
    `www.gstatic.com/generate_204` **204**；relay 计数 up 1981B / down 4713B、dial_errors=0；
  - 参照对拍（同一节点，v2ray 5.52）：gstatic/ipify 可用；`1.1.1.1`、`1.0.0.1`、
    `www.cloudflare.com` 被节点侧黑洞——sodama 逐目标与参照一致（同失败模式）。
- 回归：标准 verify 9/9；vless tcp/tls/udp 专项全过（ws 改动未影响既有路径）。

## 修订条件

需要 uTLS 指纹或 grpc/h2 传输时另写 ADR；若 Rust 生态出现可用的 TLS 指纹库，
在 `ws::connect`/`tls::connect` 的调用处替换；permessage-deflate 若成为普遍要求再评估。
真实订阅形态普查发现 **REALITY（含 xtls-rprx-vision）**与 **anytls** 属独立协议档位
（当前解析期显式拒绝，测试已钉住），需另写 ADR；过渡期可走 SOCKS5 桥接（NOTES §11.17）。
