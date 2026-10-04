# ADR-0044：QUIC Initial SNI 嗅探（P20）——解密 Initial 取 ClientHello SNI

- **状态**：已采纳（2026-10-04）
- **对应**：对标表缺口 #1「嗅探」最后一块（TLS/HTTP/h2c 已完成；余 sniff-punt）
- **相关**：ADR-0030（嗅探 + dial_mode）、ADR-0042（P18e 的 QUIC Initial 识别统计）、
  NOTES §11.21/§11.33/§11.35；对照 dae 内核侧 QUIC 嗅探

## 背景

- 嗅探栈此前覆盖 TLS SNI、HTTP/1.x Host、h2c `:authority`；QUIC（UDP 443）只做
  「长头 Initial 识别」计数（P18e），**读不到 SNI**——Initial 是加密的。
- dae 在内核侧解 QUIC Initial 拿域名（按域名分流/上报）。我们要在用户态补齐同等能力，
  作为 UDP 侧域名观测（`sniffing.quic_sni` + 日志）。

## 决策

新增 `loader/src/quicsniff.rs`（纯函数，零新依赖——复用既有 aes/aes-gcm/ring/sha2）：

1. **QUIC v1 初始密钥**（RFC 9001 §5.2）：`HKDF-Extract(固定盐, DCID)` +
   `HKDF-Expand-Label`（标签带 `tls13 ` 前缀：`client in` / `quic key` / `quic iv` / `quic hp`）。
2. **头部保护解除**（§5.4.2）：`sample = pn 字段起第 4 字节处 16B`，AES-ECB(hp) 得掩码；
   首字节低 4 位 → pn_len，还原 pn。
3. **AEAD 解密**：AAD = 解除保护后的头（首字节+pn），AES-128-GCM；nonce = iv XOR pn
   （首飞包号即截断值）。
4. **帧解析**：CRYPTO（0x06，offset 0）+ PADDING/PING；CRYPTO 内容即 handshake 消息。
5. **ClientHello → SNI**：抽公共函数 `sniffer::parse_client_hello_body`（TLS record
   路径与 QUIC CRYPTO 路径共用）。
6. **接入**：`udp_nat_handle` 新会话慢路径——长头 + ≥1200B 先计 `quic_initial`，
   再尝试解密；命中则 `quic_sni` 计数 + 日志 `quic sniff {client} → {sni}（SNI，Initial 解密）`；
   未命中静默（不误报）。
7. **边界（如实）**：仅 v1（v2 标签不同，返回 No）；仅客户端首包、单包
   （ClientHello 跨包 → No）；只做观测——UDP 拨号仍按目标地址（UDP 域名拨号未做）。

## 理由

- 用户态解密最直接：现有 AES-GCM/HKDF 原语齐全，且实现可被 **RFC 官方向量**逐字节校验
  （比内核实现更好测试）。
- 只看首包是工程折中：Chrome/quinn 的 ClientHello（含 SNI）通常落在首个 ≥1200B 的
  Initial 内；跨包需按连接缓存重组，成本/收益比差，显式记为边界。
- 观测而非拨号：UDP 代理协议目标目前是 `SocketAddr`；把 SNI 用于 UDP 域名拨号是
  协议栈级改动（ss UDP 的 ATYP 域名字段等），独立立项更合适。

## 后果

- 正面：嗅探组合（TLS/HTTP/h2c/QUIC）收齐；QUIC 域名在真机/实验室可观测；
  实现带官方测试向量，可作为后续 QUIC 相关工作的护栏。
- 负面/边界：v2、跨包 CH、0-RTT/Retry、连接迁移后重试的 Initial 不解；
  「嗅探 punt（按域名重判路由）」仍未做。

## 验证方式

- 单测（**181/181**，其中 quicsniff 5 项）：
  - RFC 9001 A.1 客户端 Initial 密钥向量逐字节比对（key/iv/hp）；
  - RFC 9001 A.2 官方保护后 Client Initial 包 → 解出 SNI **example.com**（黄金端到端）；
  - 真实 QUIC 栈（quinn）环回口首包 → 解出 `quic.sniff.test`（跨实现，防「只与自己的
    加密自洽」）；
  - 非 Initial/截断/短头/varint 边界 → 全部 No。
- lab：`udp-up` + `test-quic-sniff`——Python 夹具（`lab/quic_probe.py`，独立实现
  RFC 9001 加密）造 1200B 带 SNI 的 Initial → loader 日志与 `sniffing.quic_sni` 命中；
  `test-udp-relay` 改为前后增量断言（3 报文恰好 +1 会话），与 P20 用例可任意顺序串联。
- 回归：`verify` 9/9；`test-udp-relay`/`test-udp-idle` 全过。
- 文档：本 ADR + `docs/parity-status.md` v2.1 + `architecture-decision.html` v2.29 +
  `sodama/NOTES.md` §11.35。
