# 第三方评审存档

本目录存放外部（第三方）对 sodama 提交物的书面评审原文，以及工程方的对照采纳提案。
原则：**原文存档不改写**（仅做排版整理，评估观点不代表本项目立场）；工程方回应单独成文、逐条标注
「采纳 / 部分采纳（含修正）/ 不采纳（含理由）」，并落到 `backlog.md` 的专项编号执行。

| 文件 | 内容 |
|---|---|
| `2026-10-05-memory-final-review-a.md` | 第三方评审 A：针对 `docs/memory-report.html` v1.0（五方内存终测） |
| `2026-10-05-memory-final-review-b.md` | 第三方评审 B：同上（更强调 kernel/系统总内存与措辞边界） |
| `2026-10-05-adoption-proposal.md` | **工程方采纳提案**：事实核对（fd 拓扑/pipe 配额/内核侧初测）+ 逐条判定 + I1–I5 计划与验收 |
| `2026-10-05-i1-system-memory-data.md` | **I1 执行数据**（工程方）：四层模型口径、100–20 000 扫描、与 dae 同口径对照、20 k slab 归因、pipe capacity≠resident 结论、局限 |
| `2026-10-05-i3-forwarding-primitives.md` | **I3 执行数据**（工程方）：splice/copy/io_uring/MSG_ZEROCOPY 对照与三档选型 |

关联：评审对象 `docs/memory-report.html` v1（存档）；四层模型与系统内存结论的**现行版本**见
`docs/benchmark-report.html`（v3.0 合并版；旧 v2.1 已并入，见存档 `docs/memory-report-v2.html`）；执行项状态见 `../backlog.md` I 节。

## 生产事故复盘（工程方）

与上面的第三方评审分开归档：这些是生产环境故障的完整时间线、证据与设计教训。

| 文件 | 内容 |
|---|---|
| `2026-11-05-dns-regression.md` | 整机非正常断电 + 国内解析变慢：私网 ECS 与 `:53` 双绑 |
| `2026-11-06-node-failover.md` | 节点自动切换卡顿：串行超时、健康状态抖动、探测指标失真 |
| `2026-11-17-panel-reload-latency.md` | 面板保存配置 59 s：`watch_config` 默认关闭 + 面板不显式 reload |
