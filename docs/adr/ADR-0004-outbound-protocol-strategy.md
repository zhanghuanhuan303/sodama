# ADR-0004：outbound 协议栈——Dialer trait + 梯度推进

- **状态**：已采纳（2026-10-03）
- **对应决策点**：D4
- **相关**：ADR-0001（目标定位）、风险 R1

## 背景

代理协议实现**不在本仓库**，而在同组织的独立仓库 `daeuniverse/outbound`（`go.mod` 直接依赖）。本仓库内只有约 **1.1k 行的「怎么用协议库」**（`component/outbound/`，含 dialer、节点组、选路、健康检查）。协议清单（`component/outbound/outbound.go` 的 blank import 可见）：anytls、http、hysteria2、juicity、shadowsocks、socks5、trojan、tuic、vmess、vless 等。

Rust 生态现状：部分协议有成熟实现（如 shadowsocks 系、socks5、trojan 系），QUIC 系与 VMess/VLESS 的传输组合需要自研或适配。**外部仓库规模未知**，这是全项目最大的不确定性。

## 选项

| 选项 | 说明 |
|---|---|
| A 一开始对齐全部协议 | 范围与不确定性最大 |
| B 本期不做协议栈 | 把风险排除在范围外，但无法「可替换」 |
| **C trait + 梯度（采纳）** | **Dialer trait 抽象；按 direct/socks5/ss/trojan → VMess/VLESS → QUIC 系推进** |

## 决策

采用 C。

1. 边界定义为 `Dialer` trait（`connect(network, addr) -> impl AsyncRead+AsyncWrite` + UDP associate/FullCone 扩展），**协议实现可插拔**，与节点组、选路、健康检查解耦；
2. 梯度：**G1** direct / socks5 / shadowsocks / trojan；**G2** VMess / VLESS（含 ws/grpc/tls 传输组合）；**G3** QUIC 系（hysteria2 / tuic / anytls / juicity）；
3. 每一档都要能独立停下来并保持系统可用（未实现的协议在配置校验期报「不支持」，而不是运行期失败）；
4. 与 Go 版**同节点双跑对拍**（吞吐/延迟/兼容性），作为每档的验收门槛。

## 理由

- 协议栈是全项目唯一无法从本仓库读取规格的部分；梯度让每一档都能停机评估收益。
- Full-cone / UDP 语义（dae 明确支持 shadowsocks、trojan-go、socks5 的 full-cone）必须在 trait 设计期就表达出来，否则后期会返工。
- 健康检查/选路/粘滞（`dialer/stickyip`、`connectivity_check.go` 1,517 行）属于「与协议无关」的资产，先做可以复用。

## 后果

- 正面：最大风险被切片；用户可用性随档位递增；trait 边界使单协议测试无需整机。
- 负面/代价：G1 之前「可替换」不成立；需要维护「协议支持矩阵」文档，避免用户误解。
- 风险提示：G3 依赖 QUIC 库差异（Go 侧是定制的 `olicesx/quic-go` fork），需要专项互通测试矩阵（风险 R2）。

## 验证方式

- 每档：同节点双跑（Rust 客户端 vs Go 客户端）测吞吐/延迟/UDP 行为；
- Full-cone 用外部 STUN 探测验证；
- 兼容性用真实节点矩阵（不同服务端实现）。

## 修订条件

若 G2/G3 在合理工期（>16 周）内无法收敛，应新写 ADR：或缩小协议范围，或（若允许）以受控子进程方式复用现有 Go 协议库。
