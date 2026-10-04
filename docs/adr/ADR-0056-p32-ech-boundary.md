# ADR-0056：P32 ECH 边界——不实现客户端 ECH，解析即显式报错

- **状态**：已采纳（2026-10-04）
- **对应**：对标表缺口 #6 余项「ECH」——**如实边界**（本 ADR 即为该缺口的闭环记录）
- **相关**：ADR-0020（hysteria2 v0 边界）、ADR-0048（P24 显式边界）、ADR-0055；
  NOTES §11.47；对照 `olicesx/outbound/dialer/hysteria2/ech.go` 与
  `olicesx/quic-go`（`tls.Config.EncryptedClientHelloConfigList`）

## 背景

- dae 生态中 ECH 的唯一入口是 hysteria2 节点链接参数
  `?ech=<base64(ECHConfigList)>`：`olicesx/outbound` 校验 base64/长度后透传给
  `olicesx/quic-go` fork 的 `EncryptedClientHelloConfigList`；**真实 ECH 密码学
  与 ClientHello 重组由该 fork 完成**。dae 主体源码无 ECH。
- mini-dae 的 hysteria2 基于 `quinn + rustls`：
  - rustls 目前**没有客户端 ECH**（不暴露 ClientHello 构造，也无 ECH 钩子）；
  - quinn 要求 rustls 作为 QUIC 的 TLS 后端，无法替换成自实现栈；
  - 我方自实现的 `tls13.rs` 虽可完全控制 ClientHello（REALITY/shadow-tls v3
    已证明），但它只做 TLS-over-TCP 记录层，不能作为 QUIC 的 TLS（QUIC 需要
    CRYPTO 帧承载与包级加密）。

## 决策

1. **不实现客户端 ECH**。已有的行为保持不变并强化：
   `hysteria2://…?ech=…` 解析即返回显式错误
   （`ech 未实现（rustls/quinn 无客户端 ECH；dae 侧由 ot/quic-go fork 提供；见 ADR-0056）`），
   **绝不静默忽略**——静默忽略会把用户以为已启用的 ECH 降级为明文 SNI，属安全语义问题。
2. 以本 ADR 作为 parity「ECH 余项」的闭环：余项状态从「待做」改为「**已评估、
   明确不做（依赖边界）**」，并在 parity/HTML/NOTES 同步措辞。
3. 用单测锁定该行为（`ech` 与 `pinSHA256` 的显式拒绝），防止未来重构悄悄放行。

## 理由

- **无集成点**：ECH 需要把完整内层 ClientHello 用 HPKE 封装进外层 CH；quinn/rustls
  路径完全不暴露 CH 构造。要接入必须更换 QUIC 的 TLS 后端（自写 QUIC+TLS 栈）
  或跟随维护一个 rustls/quinn fork——两者都远超「研究性复现」的成本收益。
- **协议面成本**：完整 ECH 客户端需要 HPKE（RFC 9180：KEM/KDF/AEAD 套件）、
  draft-ietf-tls-esni 的 outer/inner CH 重组、ECHConfig 轮换与 retry_configs、
  以及和服务端发布（DNS HTTPS RR）的配合；不是「加一个参数」级别的功能。
- **生态占用低**：ECH 的面板/订阅支持仍在早期，hy2+ECH 节点占比很小；边界
  影响面有限，如实记录比勉强实现半成品更符合本项目的可信度目标。
- **依赖分叉的启示**：dae 能提供 ECH 是因为它接受了 quic-go 的 fork；本项目
  的定位是纯 Rust 上游依赖栈，引入平行分叉与该定位冲突。

## 后果

- 正面：配置作者立刻得到明确错误；无「伪 ECH」风险；parity 表述与实现一致。
- 负面/边界：使用 ECH 的 hysteria2 节点在当前栈下不可用（如实记为剩余缺口）。
- 未来若解的**前置条件**（任一）：
  1. rustls 上游提供 ECH 客户端（或暴露 ClientHello 构造钩子）且 quinn 跟进；
  2. 或 quinn 支持可插拔 TLS 后端，且我方 `tls13.rs` 扩展出 QUIC 的 CRYPTO 帧形态；
  3. 且离线 registry 提供 HPKE 依赖（或自实现 HPKE 基础模式）；
  4. 且 lab 具备 ot/quic-go ECH 服务端夹具用于跨实现验证。
  满足后按新 ADR 覆盖本条。

## 验证方式

- 单测：`hy2_ech_rejected_loudly`（ech 与 pinSHA256 均显式报错）——
  `cargo test` **236/236**。
- 行为核查：其余 hy2 参数（sni/insecure/obfs/upmbps/downmbps/udphop/cc_override）
  语义不变；lab `hy2-*` 用例回归通过（P31 批次一并跑过）。
- 文档：本 ADR + parity v2.9 + HTML v2.40 + NOTES §11.47 + README。
