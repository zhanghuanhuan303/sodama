# ADR-0003：用户态运行时——tokio 起步

- **状态**：已采纳（2026-10-03）
- **对应决策点**：D3
- **相关**：ADR-0008（部署形态）、主文档 4.3

## 背景

dae 的主路径是内核 offload（sockmap 直连）与 tproxy + splice 兜底；用户态 relay 是**兜底路径**而非主路径。Rust 侧可选：

- tokio 多线程 + 专用阻塞线程做 splice；
- thread-per-core（monoio/glommio）+ SO_REUSEPORT + shard 化连接表；
- 尽量依赖内核 offload，用户态只做最小兜底。

同时存在一个**必须解决的约束**（见 4.3 的 callout）：dae 用 `runtime.LockOSThread()` + `netns.Set()`（`control/netns_utils.go:264,496`）把 goroutine 钉在目标 netns 的 OS 线程上；**tokio 的 task 会跨线程迁移，这条路径不可行**。

## 决策

采用 tokio 起步，并配套两条硬性设计：

1. **netns 亲和改用 per-netns socket 工厂**：socket 的 netns 在 `socket()` 创建时确定，之后任何线程可用；由一个常驻目标 netns 的专用线程按需创建 socket 并把 fd 交给 tokio 任务。**不要求 task 具备 netns 亲和**。
2. **relay 热路径跑在专用 OS 线程**（`splice`/`io_uring`，阻塞式或独立 runtime），不参与 tokio 的 task 调度；控制面（配置、netlink、DNS、指标）才用 tokio。

per-core 与 io_uring 优化留到 P7，以真实剖面数据决定。

## 理由

- 主路径已在内核，用户态为兜底；在此之前引入 per-core 复杂度（跨核 janitor、netns 切换、sockmap 协调）不划算。
- per-netns socket 工厂同时消除了 dae 那一整类「线程漂移 / 忘记恢复 netns」的 bug（Go 侧用 `netns_cleanup_test.go`（28.5KB）、`listener_netns_test.go` 等大量测试在守）。
- tokio 生态完整（`rtnetlink`、`hickory`、`quinn`、`tracing`），能让 P1–P4 的进度优先于性能调优。

## 后果

- 正面：实现路径最短；netns 处理比 Go 版更健壮、更可测。
- 负面/代价：tokio 的调度与 relay 线程之间的通信必须显式设计（channel + fd 传递），不能依赖线程本地状态；后续若切 per-core，relay 层要能替换（因此 relay 与 runtime 解耦，接口先定好）。
- 需警惕：`spawn_blocking` 池不是 netns 感知的，禁止在其中直接做需要特定 netns 的操作；所有 socket 创建走工厂。

## 验证方式

- P2/P4 验收中加入「多 netns 并发创建 socket」的压力用例；
- P7 用真实流量剖面评估是否需要 per-core，并对比 P99 与 syscall 数。

## 修订条件

若 P7 剖面显示用户态 relay 成为瓶颈（而非 offload 未命中），或需要 SO_REUSEPORT 级别的核间扩展性，新写 ADR 切换到 thread-per-core。
