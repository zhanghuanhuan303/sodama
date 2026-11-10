# 研究方法与可复现性

本仓库不只是「一份能跑的代码」，也是一份可追溯的工程研究记录。目标是把「结论」与「证据」绑定：每个关键判断都能指到代码、实验、日志或数据文件；每个公开数据都能说明口径与脱敏方式。

## 1. 证据分级

文档与 PR 中使用的标记：

| 标记 | 含义 |
|---|---|
| **已实测** | 在本机/虚拟机/真实节点上跑过，并观察到结果（附命令、关键输出或数据文件） |
| **源码实测** | 通过阅读/统计源码得到（附 `文件:行号` 或统计命令） |
| **推断** | 尚未验证的判断；必须显式写「推断」并说明缺口 |

不把「看起来合理」写成事实；不把一次成功写成稳定性结论。

## 2. 三级验收

1. **单元测试**：纯逻辑、解析器、协议帧、规则编码；默认在 CI 跑。
2. **netns lab**：真实内核路径、tproxy、转发、DNS、协议梯、运维面；需要 root/特权，按 `sodama/lab/` 的会话执行。
3. **真实世界**：真实节点、真网关、公网链路、长期运行。记录环境、版本、拓扑、目标、固定后端与失败判据。

跨实现测试（与 dae/sing-box/Xray/Go 参考客户端）用于避免「只跟自家实现对得上」。

## 3. 对拍方法

- 规则编译：把同一份 `.dae` 规则交给 dae 原版 Go 编译器与 sodama，逐字节比较 kernel-space `match_set` dump（`sodama/lab/parity/`）。
- 协议：用独立参考服务端/客户端做跨实现联调，优先比较字节级帧与边界行为，而不只是「能连通」。
- 配置：发布模板必须能被 `sodama validate` 接受，并有回归测试；`docs/config-reference.md` 由代码生成器与 drift 测试锁定。

## 4. 性能与资源口径

- **进程口径**：`/proc/<pid>/task/*/schedstat`，适合比较用户态 CPU；不包含 eBPF 内核侧开销。
- **内核侧口径**：`/proc/stat` 的 system+irq+softirq，逐轮扣除前置空闲基线；用于给数据面工作量一个上界估计。
- **内存四层**：Process RSS → Kernel/Slab → Total → per-connection；避免只报进程 RSS 就宣称系统内存优势。
- **固定变量**：固定节点/固定后端/固定出口/固定目标；短传输（TLS 截断但 HTTP 200）要按字节数判失败并重试；不同实现串行测量，记录顺序。
- 任何性能结论都要附「口径 + 数据文件 + 脚本入口」，并注明未覆盖项。

## 5. 测试数据与脱敏规则

公开仓库保留测试方法、脚本、相对结论与脱敏后的数据；**不保存真实订阅 URL、token、节点域名、节点 IP、生产路由器地址、凭据或可识别个人的信息**。

脱敏约定：

| 类型 | 公开版写法 |
|---|---|
| 订阅端点 | `https://subN.example.com/sub?token=REDACTED` |
| 节点域名/SNI | `node-a.example.com` / `sni.example.com` |
| 公网 IPv4 | RFC 5737 文档地址：`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24` |
| 公网 IPv6 | RFC 3849 文档地址：`2001:db8::/32` |
| 生产主机/路由器 | `root@192.0.2.10` 或 `user@host` |
| MAC | `02:00:00:00:00:42` 等本地管理地址 |

原始未脱敏数据只保留在私有工作区，不进入公开 git 历史。提交前请用仓库的敏感字符串检查脚本（或 `grep`）自查。

## 6. 复现入口

```bash
# 构建
cd sodama && lab/lab.sh build

# netns 拓扑与 9 用例
sudo lab/lab.sh up
sudo lab/lab.sh verify
sudo lab/lab.sh down

# 规则对拍（需要同级 clone dae）
lab/parity.sh

# 性能/内存
sudo lab/perf/run.sh all
sudo lab/perf/mem-system.sh
```

具体会话清单、环境要求与已知边界见 [`../sodama/README.md`](../sodama/README.md)、[`../docs/benchmark-report.html`](../docs/benchmark-report.html) 与 [`../docs/parity-status.md`](../docs/parity-status.md)。

## 7. 已知边界

- GitHub Actions 只跑「编译 + 单测」；需要 root/特权内核的 lab 用例在真机/QEMU 中执行，这是明示边界。
- 部分协议实现是子集（例如 SSR auth/obfs 家族、ECH、某些插件），未实现项在 ADR/backlog 中登记，不静默丢弃。
- 生产长期运行数据来自特定硬件/内核/网络；结论用于工程判断，不构成普适保证。
- 公开版的历史数据经过脱敏，节点侧抖动等外部因素仍可能影响吞吐/延迟的绝对值；相对排序与口径才是主要结论。
