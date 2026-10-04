# ADR-0045：sniff-punt（P21）——嗅探域名在 relay 侧用户态重判路由

- **状态**：已采纳（2026-10-04）
- **对应**：对标表缺口 #1「嗅探」最后一块（按嗅探域名重判路由）
- **相关**：ADR-0030（嗅探 + dial_mode）、ADR-0044（QUIC SNI）、ADR-0043（多组分派）、
  NOTES §11.36；对照 dae `sniffing` 的内核/控制面 punt 语义

## 背景

- dae 在嗅探到域名后可「punt」——按域名重新跑一遍路由（direct/block/组），弥补
  `dial_mode: ip` 下域规则只能用 DNS 位图的不足。
- sodama 此前：`dial_mode != ip` 时嗅探只把**拨号目标**换成域名（远端解析），
  **出口选择仍完全依赖数据面**（DNS 位图 + conn_state 回读）。对「客户端直接连 IP、
  TLS 内嵌 SNI、且 DNS 不经我们」的流量，域规则无从生效。

## 决策

1. **用户态规则 VM**（`rules.rs`）：新增 `PuntCtx`（domain/dip/sip/dport/sport/l4proto）
   与 `PuntOutcome`（Outbound/NoMatch/ControlPlane），`CompiledRules::punt_match`
   逐条对照 `ebpf-rs/src/route.rs` 的 state 机与 logical OR(0xFE)/AND(0xFF)/must 编码：
   - 复用编译期产物：域集合走 `dns::domain_set_matches`（suffix/full/keyword/regex 索引），
     IP 走 `lpm_tries` 前缀匹配（v4-mapped 统一 16 字节）；
   - dport=53 且非 must → `ControlPlane`（与数据面一致：保持控制面接管）；
   - 未掌握字段（mac/dscp/pname）按**不命中**处理（LAN→WAN 转发的连接在数据面
     `is_wan=0`，pname 恒不命中；mac/dscp 用户态不可得——见 ADR 后果）。
2. **relay 接入**（`main.rs::handle_relay_conn`）：`--sniff-punt`（或 config
   `global.auto_sniff_punt: true`）且嗅探命中域名时重判：
   - `direct` → 不走组拨号，**直连原始目的 IP**（与内核 direct 行为一致，不本地解析 SNI）；
   - `block` → 立即关闭连接并计数；
   - 用户组 → 按 outbound 索引换组拨号（`group_dialer_by_outbound`，复用 P19 组表）；
   - NoMatch/ControlPlane/无组映射 → 保持数据面/默认决策（punt_keep 计数）。
   - mark/must 只记录日志（SO_MARK 属数据面语义，用户态拨号不承载）。
3. **可观测**：`sniffing.punt_enabled/punt_attempts/punt_direct/punt_block/punt_group/punt_keep`
   状态面 + 日志 `punt <域名>（<orig>）→ direct|block|outbound 0xNN（组 …）`。

## 理由

- 复用数据面同一套编译产物与编码（含 not/AND/OR 粘性语义），避免「第二套规则引擎」
  长期漂移；单测直接对照 route.rs 的判定顺序。
- 默认关闭：不开 `--sniff-punt` 行为与 P20 完全一致，回归风险为零；开启需要
  `dial_mode domain/domain+`（未嗅探无域可判，启动时明确提示）。
- direct 直连原始 IP：客户端本就是以 IP 建连，SNI 仅用于**选路**；避免为直连引入
  一次本地 DNS 解析（也可能被污染）。

## 后果

- 正面：域规则对「IP 连接 + 内嵌 SNI」流量生效；嗅探四类（TLS/HTTP/h2c/QUIC 观测）
  中 TLS/HTTP/h2c 路径可 punt；与多组分派正交（组重选被 lab 双 ss 交叉验证）。
- 负面/边界：mac/dscp/pname 规则在重判中不参与（文档化，不静默误判——命中的槽位
  按不命中走，可能比数据面「更宽」）；UDP（QUIC）仅观测、不 punt；重判发生在
  连接已进 relay 之后，意味着「本可直连」的流量多付一跳 relay（嗅探是前提，可接受）。

## 验证方式

- 单测（rules.rs 5 项）：域重选/子域大小写、`!domain`+AND 失败传播、dport 多值
  sticky-OR、sip/dip/端口组合、dport=53 → ControlPlane；不命中回落 fallback 组索引。
- lab `sniff-punt-up` + `test-sniff-punt`（配置面 `auto_sniff_punt` + 双组双 Python ss）：
  1) `direct.test` → 日志 `→ direct`、直连回显成功、ss-A 无该目标（仅健康检查）；
  2) SNI `1.1.1.1`（full 域规则）→ 重判到 alt 组，ss-B 日志有 `TCP target=1.1.1.1:8080`、
     ss-A 无；3) `blocked.test` → 连接被关闭；状态面 punt_direct/block/group 均 ≥1。
- 回归：`cargo test --release` 202/202；lab `verify` 9/9（嗅探默认关）。
- 文档：本 ADR + parity v2.2 + HTML v2.30 + NOTES §11.36。
