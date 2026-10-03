# ADR-0009：先做内核切片（K 轨道），取代 ADR-0007 的顺序

- **状态**：已采纳（2026-10-03）
- **取代**：[ADR-0007](./ADR-0007-priority-order.md)（配置 + 路由先行）
- **对应决策点**：D7（已修订）
- **相关**：ADR-0002（数据面语言）、ADR-0004（协议栈）、ADR-0008（部署形态）

## 背景

ADR-0007 把「配置 + 路由」放在第一步，理由是无需 root、可用 Go 版逐条对拍、fan-in 最高。实际推进时出现了一个更符合项目目标的顺序：**先把不确定性最大的内核侧变成确定**。

需要澄清一个概念张力：「内核攻坚」与「eBPF 分流」不能是两件事——

- 数据面不能独立存在：它的每个判决都由用户态编译进 map，没有驱动就只能手写 map 做合成测试；
- 没有对拍手段，eBPF 的问题大多不报错、只表现为行为错误，无法判断「跑通了」还是「碰巧跑通了」。

## 决策

改为 **K 轨道先行**，并把「内核攻坚」重新定义为纵向切片：

```
K0 数据面工作台   bpf_loop 规则 VM + LPM array-of-maps + 双 epoch 槽
                  + conntrack 基础 + redirect_track 单写者
K1 最小驱动       routing 子集编译 + 钩子集合管理（lan/wan/dae0/dae0peer/单臂）
                  + listener/sockmap + 生命周期与 reload
K2 对拍与内核矩阵 map/判决对拍自动化 + 内核矩阵（5.17/6.1/6.6/6.14+）+ 故障注入
K3 生态接入       全量 .dae 解析 + 只读状态面 +（可选）Go 后端过渡一跳
（之后回到 P3 DNS → P4 relay/offload → P5 协议栈 → P6 运维面）
```

配套约束：

1. **生态接入用契约级/进程级边界**：配置 DSL、订阅格式、协议矩阵、状态面。**禁止 cgo/FFI 复用 Go 库**（会把 Go 运行时与 GC 一起搬回来，丢掉重写的核心收益）。
2. 可选过渡形态：**把 Go dae 当协议后端**（Rust 负责内核侧，代理流量经本地 socks5/tproxy 一跳交给 Go 实例），使内核侧能立刻用真实节点测试。
3. Go 版 40k 行测试**不可直接复用**（多依赖内部 API），复用其**场景与夹具**（`example.dae`、DNS corpus、规则用例），黑盒化重写。
4. 数据面**兜底路径**：若 Rust eBPF 化受阻，回退到 C 数据面（mini-dae 已验证 aya 可加载 C 对象），控制系统仍按 Rust 交付。

## 理由

- 风险最集中：verifier 约束、内核矩阵、ABI（map 布局/打包位/枚举）一旦定型最难返工；先把它变成确定，后续所有模块都受益。
- 工具链已验证：mini-dae 已跑通「aya 加载 + 跨 netns TCX 钩子 + sk_assign 交付 + LPM map-in-map」。
- 对拍可以缩小：K0/K1 只需要「map dump + 包级 e2e」这一最小对拍器，不必等完整 oracle 基建。
- 内核侧沉淀的资产（数据面工作台 + netns 实验场）会被后续每个模块复用。

## 后果

- 正面：最先消除最大不确定性；ABI 与共享类型（`dae-ebpf-shared`）尽早定型；数据面工作台可长期复用。
- 负面/代价：`validate/export` 这类「立刻可用的产物」推迟 2–3 个月；路由编译器必须提前做一个**子集**（只覆盖 `dip/sip/mac/l4proto/ipversion/dport/sport/dscp/fallback`），全量 DSL 留到 K3。
- 风险：K 轨道若卡在 verifier/内核细节，项目会出现「没有可用产物」的空窗期 → 见第 4 条兜底。

## 验证方式（K0 已完成的第一步，实测）

- 规则编码与 dae 对齐：`IpSet(0xff=LogicalAnd) → Port(0x02)`、`not=1`、`mark/must` 均按 dae 的 `matcher_builder.go:60-73` 编码；
- 数据面：9 个 match_set、3 个 LPM trie（map-in-map 插入成功，`bpftool` 可见 `inner_map_id`）；
- 包级 e2e：**proxy**（`orig_dst=1.1.1.1:8080`）、**direct**（LPM 集合的第二个前缀 `10.9.10.2`）、**block**（NOT+AND 编码 + 丢弃，未进入用户态）三项全通；
- 5 个编译器单元测试覆盖 `&&`/OR 折叠/`!`/`mark,must`/跨规则 LPM 下标重定位。

## 修订条件

若 K0/K1 在 4 周内无法通过内核矩阵（或 verifier 行为与 C 版本出现不可解释的差异），回退到「C 数据面 + Rust 控制面」，并把顺序改回 ADR-0007 的 P1 优先——此时应新写 ADR 记录回退原因与新的顺序。
