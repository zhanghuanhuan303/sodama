# ADR-0008：部署形态——常驻进程 + eBPF 分流，不接管 direct

- **状态**：已采纳（2026-10-03）
- **对应决策点**：D8
- **相关**：ADR-0003（运行时）、主文档 4.5 / 4.6

## 背景

需求是「以常驻 Rust worker 的形式部署，接管流量并由 eBPF 分流」。这里有两个方向相反的概念必须拆开：

- **eBPF 分流**：只有需要代理的流量进用户态，direct 流量在内核三层转发完成；
- **接管所有流量**：所有包都经过用户态 worker。

同时，部署形态受两个既有事实约束：

1. **eBPF 数据面是 per-netns 单例**：钩子按优先级串行，多进程各挂一套会互相覆盖；
2. **dae 用 `runtime.LockOSThread()` + `netns.Set()` 做 netns 亲和**（`control/netns_utils.go:264,496`），该模式与 tokio 的 task 跨线程迁移不兼容。

故障语义实测：现代内核上 dae 优先使用 **TCX**（`control/tc_hook_set.go:199`），钩子是 bpf_link，**进程退出即摘除**（mini-dae 已验证）→ 分流消失、流量回落为普通转发。

## 决策

1. **形态 A：eBPF 分流 + 用户态只处理代理流量**。即「接管所有流量的**决策**，只接管需要代理的**数据**」。不采用 worker 全接管（形态 B），也不采用 TUN + 用户态 TCP/IP 栈（形态 C）。
2. **数据面所有权单例**：supervisor 负责加载/挂载/拥有 map（bpffs pin）与创建 tproxy listener；listener 以 **fd 继承**（fork 或 SCM_RIGHTS）交给 worker；worker 只 `accept` 与 relay。
3. **第一版单进程多线程**（tokio + 专用 relay 线程 + per-netns socket 工厂），worker 边界先做成任务边界；进程级隔离在需要时再拆（supervisor + N workers）。
4. **netns 一致性用 per-netns socket 工厂**，不依赖线程亲和：socket 的 netns 在创建时确定，之后任何线程可用。
5. **故障语义默认 fail-open**：TCX + systemd `Restart=on-abnormal`（5s）+ map pin 热恢复。对隐私/合规敏感场景，提供**心跳死区**开关：用户态周期性刷新 timestamp map，数据面超时后对 proxy 判决返回 DROP（fail-closed 变体）。
6. 需要「看到每一个包」的审计/DLP 需求，用 **eBPF 镜像**给旁路进程解决，而不是把 worker 串接进数据路径。

## 理由

- 形态 B 会把 direct 流量的成本从一次内核路由查找变成两次拷贝 + relay + 2×socket 操作，并让故障域从「部分功能降级」变成「整机断网」；dae 专门设计 Real Direct 就是为了避免这一点（其文档解释了为何不做全接管）。
- 拆进程的收益（崩溃隔离、独立重启、CPU 隔离）在「eBPF 已承担主路径」的前提下有限，而代价（fd/netns/map 共享复杂度）真实存在，因此不作为第一版目标。
- per-netns socket 工厂同时消除 dae 一整类「线程漂移 / 忘记恢复 netns」的缺陷（Go 侧用 28.5KB 的 `netns_cleanup_test.go` 等测试在守），是 Rust 版可以做得更好的点。

## 后果

- 正面：保住 Real Direct；故障域可控；netns 处理更健壮；部署契约（systemd）可直接沿用 dae 的 unit 设计（`install/dae.service`）。
- 负面/代价：需要显式管理「数据面单例」的所有权与生命周期（这本身是复杂度，只是被集中到 supervisor）；用户态 relay 的热路径被限定在专用线程，接口需要提前解耦。
- 需注意：内存要分三块账（用户态堆 / BPF map / page cache），其中 BPF map 的条目预算必须显式化并在启动时校验 memlock。

## 验证方式

- P2 验收：单进程形态下 direct/proxy/回程 e2e 通过（mini-dae 已给出最小闭环），进程退出后钩子摘除且流量回落正常；
- 故障注入：kill -9 supervisor，验证 fail-open 行为与 5s 内恢复；
- 若启用死区开关：停止心跳，验证 proxy 判决转为 DROP 且 direct 不受影响；
- 多 netns：并发创建 socket 的压力用例（见 ADR-0003）。

## 修订条件

- 若容器化部署成为主场景（per-netns worker 需求），新写 ADR 定义 per-netns 数据面的所有权与共享模型；
- 若出现必须在用户态看到全部报文的硬需求，新写 ADR 评估形态 B/C，并明确其性能与故障域代价。
