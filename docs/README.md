# 文档体系

本目录存放对 dae 的分析、重构设计与决策记录。目标是：**每个结论都能追溯到代码或实验**，并且可以随着上游更新重新生成。

## 目录约定

```
docs/
├── README.md                     # 本文件：索引与约定
├── sodama-atlas.html             # ★ 开发研究图集（Atlas）v2.0（重写版）：当期状态文档——能力地图（15 域）+ 架构 + 性能与资源边界（本机全量强度轮 + 真实 CF 节点公网轮）+ 方法论 + 踩坑档案（16 则）+ 生产实战（多轮 72h 链与新引擎轮）+ A–J 类余项地图；Tufte 版式，自包含可离线打开
├── phase2-devlog.md              # 第二阶段（生产实战轮）开发记录：侦查/修复/验收（§1–§19）+ 附 A 工具 / 附 B 监控台账
├── security-proposal.md          # 安全工程提案 v0.1：威胁模型 / 攻击面清单 / 供应链缺口 + S0–S5 排期（待采纳）
├── memory-safety-audit.html      # ★ 内存安全与资源生命周期审计（unsafe 专项）v1.1：loader + ebpf-rs 全量 unsafe 审读（167 块/19 fn/10 impl）· 3 高 4 中 13 低 + 已核销清单 + **2d5h39m 生产实况比对（H2 实锤/M4 证伪降级）** + 修复批次（已实施未部署）
├── architecture-decision.html    # 决策档案（主文档，自包含可离线打开）
├── parity-status.md              # 对标进度：dae（Go）↔ sodama（全 Rust）分域覆盖度
├── benchmark-report.html         # ★ 性能与资源边界报告 v3.0（合并版）：吞吐四方对拍 + 四层内存模型 + FD 治理 + 转发原语 + 五万并发压测 + 长稳
├── benchmark-report-v4.html      # ★ 性能与资源边界报告 v4.1 · 本机全量强度轮 + 真实 CF 节点公网轮（2026-10-16～17）：补全后数据面复测 + 四专题回归分析（R11 拒载 · lab offload 口径 · ss/UDP 二分 · real.sh 口径）；数据源 docs/reviews/2026-10-16-local-full-bench/ 与 docs/reviews/2026-10-17-real-node-cf-edge/
├── perf-report.md                # （已并入 benchmark-report.html）性能对比 · 历史存档
├── vless-proposal.html           # VLESS 性能实测与优化提案（自包含 HTML，可离线打开）
├── memory-report.html            # （已并入 benchmark-report.html）内存终测 v1.0 五方 RSS · 历史存档
├── memory-report-v2.html         # （已并入 benchmark-report.html）系统内存与资源边界 v2.1 · 历史存档
├── project-summary.html          # 项目总结报告（整体工程：历程/架构/对标/性能/路线，自包含 HTML）
├── openwrt.md                    # OpenWrt 支持（musl 构建/内核 fragment/ipk/procd/QEMU 冒烟）
├── reviews/                      # 第三方评审存档（原文）+ 工程方采纳提案（I1–I5）
├── optimization-roadmap.md       # 优化方向（数据驱动，O1–O10 优先级与验收）
├── dae-optimization-research.md  # ★ 面向 dae 的优化与创新研究：已做/能做清单、三条迁移路线、负面结论（dev 分支）
├── adr/                          # 已采纳决策记录（ADR-0001..0065）
├── modules/                      # 模块级规格（tuic-v5-client-spec.md / hysteria2-client-spec.md，由源码研究产出）
└── migration/                    # (待建) 迁移日志与对拍报告
```

相关但不在本目录：

| 文档 | 位置 | 内容 |
|---|---|---|
| 决策记录（ADR） | `adr/` | 已采纳决策的背景/选项/后果/验证方式，共 30 条（D1–D8；0007 被 0009 取代，0010–0015 记录 K2/K3/P3/P4 口径，0016 = P5-G1，0017 = P5-G2，0018 = P5-G3a，0019 = P5-G3b，0020 = P5-G3b+，0021 = P6，0022 = P7，0023 = P8，0024 = P9，0025 = 移除 C 数据面，**0026 = P10 vless-ws，0027 = P11 anytls，0028 = P12 socks 入口，0029 = P13 真网关模式，0030 = P14 嗅探 + dial_mode，0031 = P15 订阅/节点组/健康检查**） |
| 对标进度 | `parity-status.md` | dae（Go）↔ sodama（全 Rust）分域覆盖度对照（15 域 + 汇总 + Top 缺口 + 优势项，附证据锚点） |
| VLESS 提案 | `vless-proposal.html` | VLESS（明文/TLS）四方实测 + perf 剖面 + 分阶段优化提案（自包含，可离线打开） |
| 内存终测 | `memory-report.html` v1 / `memory-report-v2.html` v2.1 | v1：五方 RSS 对照（存档）；v2.1：四层模型系统内存（内核侧/Slab 归因/FD 治理/转发原语/I6 零线程 + 60 min 长稳），送审版 |
| **性能与资源边界（现行）** | `benchmark-report.html` | **v3.0 合并版**：吞吐四方对拍 + 四层内存模型 + FD 治理 + 转发原语对照 + **五万并发压测** + 长稳；自包含可离线打开（旧三份报告已并入，保留存档） |
| **开发研究图集（总览入口）** | `sodama-atlas.html` | **Atlas v2.0（重写版）**：当期状态文档（v1.x 增量叙事收敛；历史批次细节留 devlog/专题报告）——能力地图（15 域）、架构总览、性能与资源边界（本机全量强度轮 + 真实 CF 节点公网轮，内联 SVG 图）、工程方法论（三级验收/口径纪律）、踩坑档案（16 则）、**生产实战轮（多轮 72h 链 + 新引擎轮）**、**A–J 类余项地图（J 类 = 面板能力面）**、ADR 与数据源索引；Tufte 书卷版式，自包含可离线打开 |
| 第二阶段开发记录 | `phase2-devlog.md` | 生产实战轮逐条记录（问题 → 侦查 → 结论 → 动作 → 验收，§1–§24）：四轮侦查/修复 + 72h 生产测试 + **A2 收口后的修复轮 / 旧 72h 轮收口 / 新引擎上线与新 72h 起点（§24）** + 附 A/B 台账 |
| 安全工程提案 | `security-proposal.md` | 攻击面取证（9 类输入 × 解析器 × 防线）+ 供应链 6 项缺口 + S0–S5 排期（fuzz ≥8 目标 / QEMU 特权加载 CI / cargo-deny / panic 面），**待采纳** |
| 项目总结 | `project-summary.html` | 整体工程总结：阶段历程/架构总览/对标完成度/性能与内存汇总/工程质量/部署生态/后续路线（自包含，可离线打开） |
| 第三方评审 | `reviews/` | 评审原文存档（内存终测 A/B）+ 采纳提案 + I1 系统内存数据 + I3 转发原语对照 |
| OpenWrt | `openwrt.md` | musl 交叉构建、内核 fragment（NAMESPACES/NET_NS 关键项）、ipk/procd/uci、拓扑集成与 QEMU 冒烟 |
| 数据面核心笔记 | `sodama/NOTES.md` | eBPF 分流/tproxy/回程机制的源码级笔记（带行号） |
| 实验手册 | `sodama/README.md` | sodama 的构建、拓扑、测试与实测输出 |
| 上游文档 | `dae/docs/{en,zh}/` | dae 官方文档（how-it-works、配置、内核参数） |

## 证据分级

写结论时必须标注来源等级，避免「看起来对」的推断被当成事实：

| 标记 | 含义 |
|---|---|
| **已实测** | 在本机跑过并观察到结果（如 sodama 的 proxy/direct 路径、TCX 挂载） |
| **源码实测** | 通过静态统计/全文阅读得到（如 LOC、import fan-in、`tproxy.c` 行号） |
| **推断** | 未验证的判断（如工期、性能收益、外部仓库规模），必须显式写出「未验证」 |

引用代码时使用 `文件:行号`（例如 `control/kern/tproxy.c:2196`）。

## 重新生成统计数据

主文档中的规模/依赖数字来自以下命令（在 dae 仓库根目录执行）：

```bash
# 源文件/测试文件数与 LOC（按顶层模块）
python3 - <<'PY'
import os, collections
src=tst=0; sql=tql=0
for dp,dns,fns in os.walk('.'):
    dns[:] = [d for d in dns if d not in ('.git','go-mod') and not d.startswith('.')]
    for f in fns:
        if not f.endswith('.go'): continue
        n=sum(1 for _ in open(os.path.join(dp,f),encoding='utf-8',errors='ignore'))
        if f.endswith('_test.go'): tst+=1; tql+=n
        else: src+=1; sql+=n
print(f"src={src} test={tst} loc={sql} testloc={tql}")
PY

# 数据面规模
wc -l control/kern/tproxy.c
grep -c 'SEC("\.maps")' control/kern/tproxy.c      # map 数
grep -o 'BPF_MAP_TYPE_[A-Z_]*' control/kern/tproxy.c | sort | uniq -c

# 外部直接依赖
go mod edit -json | python3 -c "import json,sys; d=json.load(sys.stdin); \
  print('\n'.join(r['Path'] for r in d['Require'] if not r.get('Indirect')))"
```

> 注意：`go list -deps` 需要 module 代理网络；若不可用，用内部 import 的正则统计近似（主文档 1.4 的 fan-in 即此法）。

## 文档更新规则

1. 上游 dae 更新后：重跑上面的统计命令，更新主文档 1.2 / 1.4 / 附录 A·B，并在文档页脚更新版本与 commit。
2. 每次实验（如 sodama 新增验证点）：在 `sodama/README.md` 记录命令与输出，在主文档对应处加 **已实测** 标记。
3. 每个待拍板项一旦决定：在 `docs/adr/` 建一条 ADR（编号、背景、选项、决定、后果），并在主文档节 08 的对应卡片上标注结论。

## 版本

| 文档 | 版本 | 基于 |
|---|---|---|
| `architecture-decision.html` | v2.43 · 2026-10-04 | dae `main@e3fee8f`（tag `nightly`） |
| `parity-status.md` | v2.20 · 2026-10-17 | 同上（修复轮 + 面板 v2.0 后清点；覆盖度为功能点粗估，十五域逐行附证据；域 1 eBPF ≈95%、协议 ≈86%（主流 ≈99%）） |
| `sodama-atlas.html` | **v2.0 · 2026-10-17** | **总览入口（重写版）**：main@cb62dd0 基线；汇总 parity-status v2.20 / benchmark-report-v4 v4.1 / memory-safety-audit v1.1 / phase2-devlog §1–§24 / reviews / backlog（A–J 类）/ ADR-0001..0069，附全部实测数据与口径纪律（§5.3）；v2.0 为当期状态文档——本机全量强度轮（四方四路径）+ 真实 CF 节点公网轮 + 内存四层/五方 + 生产 72h 链（含新引擎轮） |
| `phase2-devlog.md` | §1–§24 · 2026-10-17 | 第二阶段（生产实战轮，10-08 起）：侦查/修复/验收；P37/P37b 额度治理（§13–§14）+ AF-XDP 预研（§15）+ 72h 测试（§16）+ **审计修复批次与 2d5h39m 生产比对（§17）** + **修复批上线回验与新一轮 72h 启动（§18）** + **数据面对标批次（§19）** + **A2 收口修复轮（§24：R11/UDP GSO/reactor 分派/lab 口径/ws 干净 EOF/musl）· 旧 72h 收口 · 新引擎上线与新 72h 起点** |
| `security-proposal.md` | v0.1 · 2026-10-11 | 评审意见回应稿（**待采纳**）：main@0bcadc6 取证；附录 A 为 backlog 重分类建议（新增 S 类） |
| `memory-safety-audit.html` | **v1.1 · 2026-10-16** | **unsafe 专项审计 + 生产比对 + 修复批次（已部署并回验）**：dev@d1bdb46 基线；全量审读 + clippy 实跑；§8 = 2d5h39m 生产数据比对（H2 实锤 3s/1.4万次重连每天；M4 证伪降级；H1/H3/M1/M2/M3 零暴露）；§9 = 修复批次（H1/H2/H3/M1/M2/M3 + L1/L2/L5，287/287 测试、OpenWrt 构建通过，**2026-10-16 05:44 部署**：DoH 连接 40s 端口不变、空闲 dial-wd=0）；新一轮 72h 进行中（devlog §18） |
| `benchmark-report-v4.html` | **v4.1 · 2026-10-16/17** | **本机全量强度轮 + 真实 CF 节点公网轮**：main@e5db7fd + 四项修复基线；四方吞吐（vless/ss/tls）/ 并发扩展 / 内存五方 / 四层 100→50k / UDP / codec 压 / 60min 长稳；含 R11 验证器拒载修复、lab offload 口径修正、ss reactor-codec 回归二分（b030f90）、UDP GSO 回归二分（e5db7fd）；**§11 真实订阅节点（CF 边缘 worker）公网轮**：17 轮 ×（sodama/dae/sing-box/direct），进程口径 sodama 较 dae −31%、较 sing-box −28%；原始数据 `reviews/2026-10-16-local-full-bench/`、`reviews/2026-10-17-real-node-cf-edge/` |
| `benchmark-report.html` | **v3.0 · 2026-10-06** | **现行合并版**：吞吐四方对拍（perf-report）+ 四层内存模型/FD 治理/转发原语/长稳（memory-report-v2.1）+ 五方 RSS 存档（v1）+ 五万并发压测与 fd 硬限修复（本轮）；由 `sodama/lab/perf/gen-benchmark-report.py` 生成 |
| `memory-report.html` | v1.0 · 2026-10-05 | 已并入 `benchmark-report.html` §6/附录 A · 存档 |
| `memory-report-v2.html` | v2.1 · 2026-10-05 | 已并入 `benchmark-report.html` §4/§5/§8/§9 · 存档 |
| `perf-report.md` | P33.2 · 2026-10-04 | 已并入 `benchmark-report.html` §3/附录 A · 存档 |
| `project-summary.html` | v1.0 · 2026-10-05 | 整体工程总结（main@c669ece 基线；OpenWrt P0 应用侧、自编内核冒烟暂停） |
| `openwrt.md` | v1.0 · 2026-10-05 | OpenWrt 24.10+（内核 ≥6.6 + fragment）；x86_64/aarch64/armv7 musl 构建 |
| `adr/ADR-0001..0031` | 已采纳 · 2026-10-04 | 同上；D1–D8 决策（0007 被 0009 取代；0010 = K2；0011 = K3；0012 = P3a；0013 = P3b-1；0014 = P3b-2a；0015 = P4；0016 = P5-G1；0017 = P5-G2；0018 = P5-G3a；0019 = P5-G3b；0020 = P5-G3b+；0021 = P6；0022 = P7；0023 = P8；0024 = P9；0025 = 移除 C 数据面；0026 = P10 vless-ws；0027 = P11 anytls；0028 = P12 本地 SOCKS5 入口；0029 = P13 真网关模式；0030 = P14 嗅探 + dial_mode；0031 = P15 订阅/节点组/健康检查） |
| `sodama/`（K0–K3 + P3–P12 工作台） | 已完成 · 2026-10-04 | ……（P7 剖面/soak/静态发布）+ P8/P9 数据面 Rust 化（8 程序/14 map 全量移植、BTF maps、默认数据面切 Rust）+ **P9+ 移除 C 数据面（单一 Rust 对象，ADR-0025）与完整性回归**（DNS 6/6、转发面 6/6、协议梯 15 会话 17/17、运维 5/5、对拍 5/5、联调 3/4（1 为已知 Go 客户端偏差）、双内核矩阵 9/9、soak 三模式无泄漏；见 NOTES §11.16）+ **P10 vless-ws（ADR-0026/§11.17）+ P11 AnyTLS（ADR-0027/§11.18，真实节点 e2e 204）+ P12 本地 SOCKS5 入口（ADR-0028/§11.19，浏览器验收 YouTube 200）与 P13 真网关模式（ADR-0029/§11.20，`--lan none` + `lab/gateway.sh`，宿主流量透明接管：204/YouTube 200、出口 IP=节点侧、down 后无残留）** |
