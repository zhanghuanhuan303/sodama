# 文档体系

本目录存放对 dae 的分析、重构设计与决策记录。目标是：**每个结论都能追溯到代码或实验**，并且可以随着上游更新重新生成。

## 目录约定

```
docs/
├── README.md                     # 本文件：索引与约定
├── architecture-decision.html    # 决策档案（主文档，自包含可离线打开）
├── adr/                          # 已采纳决策记录（ADR-0001..0025）
├── modules/                      # 模块级规格（tuic-v5-client-spec.md / hysteria2-client-spec.md，由源码研究产出）
└── migration/                    # (待建) 迁移日志与对拍报告
```

相关但不在本目录：

| 文档 | 位置 | 内容 |
|---|---|---|
| 决策记录（ADR） | `adr/` | 已采纳决策的背景/选项/后果/验证方式，共 27 条（D1–D8；0007 被 0009 取代，0010–0015 记录 K2/K3/P3/P4 口径，0016 = P5-G1，0017 = P5-G2，0018 = P5-G3a，0019 = P5-G3b，0020 = P5-G3b+，0021 = P6，0022 = P7，0023 = P8，0024 = P9，0025 = 移除 C 数据面，**0026 = P10 vless-ws，0027 = P11 anytls**） |
| 数据面核心笔记 | `mini-dae/NOTES.md` | eBPF 分流/tproxy/回程机制的源码级笔记（带行号） |
| 实验手册 | `mini-dae/README.md` | mini-dae 的构建、拓扑、测试与实测输出 |
| 上游文档 | `dae/docs/{en,zh}/` | dae 官方文档（how-it-works、配置、内核参数） |

## 证据分级

写结论时必须标注来源等级，避免「看起来对」的推断被当成事实：

| 标记 | 含义 |
|---|---|
| **已实测** | 在本机跑过并观察到结果（如 mini-dae 的 proxy/direct 路径、TCX 挂载） |
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
2. 每次实验（如 mini-dae 新增验证点）：在 `mini-dae/README.md` 记录命令与输出，在主文档对应处加 **已实测** 标记。
3. 每个待拍板项一旦决定：在 `docs/adr/` 建一条 ADR（编号、背景、选项、决定、后果），并在主文档节 08 的对应卡片上标注结论。

## 版本

| 文档 | 版本 | 基于 |
|---|---|---|
| `architecture-decision.html` | v2.11 · 2026-10-04 | dae `main@e3fee8f`（tag `nightly`） |
| `adr/ADR-0001..0027` | 已采纳 · 2026-10-04 | 同上；D1–D8 决策（0007 被 0009 取代；0010 = K2；0011 = K3；0012 = P3a；0013 = P3b-1；0014 = P3b-2a；0015 = P4；0016 = P5-G1；0017 = P5-G2；0018 = P5-G3a；0019 = P5-G3b；0020 = P5-G3b+；0021 = P6；0022 = P7；0023 = P8；0024 = P9；0025 = 移除 C 数据面；0026 = P10 vless-ws；0027 = P11 anytls） |
| `mini-dae/`（K0–K3 + P3–P11 工作台） | 已完成 · 2026-10-04 | ……（P7 剖面/soak/静态发布）+ P8/P9 数据面 Rust 化（8 程序/14 map 全量移植、BTF maps、默认数据面切 Rust）+ **P9+ 移除 C 数据面（单一 Rust 对象，ADR-0025）与完整性回归**（DNS 6/6、转发面 6/6、协议梯 15 会话 17/17、运维 5/5、对拍 5/5、联调 3/4（1 为已知 Go 客户端偏差）、双内核矩阵 9/9、soak 三模式无泄漏；见 NOTES §11.16）+ **P10 vless-ws 真实订阅节点（ADR-0026/§11.17）+ P11 AnyTLS 客户端（ADR-0027/§11.18，真实节点 e2e 204）** |
