# 面向 dae 的优化与创新研究

> **一句话**：这是一份「技术转移文档」——把 sodama（dae 的全 Rust 重写）在
> **重写全线（ADR-0001..0063、单测 280+）与生产实战（软路由在线 70+ 小时，
> §12 72h 测试进行中）**中验证过的优化组合、以及被实测否定的方向，
> 整理成 dae 谱系可以走的**已做 / 能做**清单与实现路径。
>
> **口径**：所有数字来自本仓库实测（可追溯文件逐条标注）；对 dae 的判断引用
> `dae/`（Go 上游）与 `docs/parity-status.md` 的源码清点，不转述未验证的传闻。
> **强调**：这不是「Rust 更好」的宣传册——第 3 节专门记录**我们以为会赢、但实测没赢**
> 的方向，那些结论可能比优化本身更值钱。

| 输入材料 | 用途 |
|---|---|
| `docs/benchmark-report.html`（v3.0 合并版） | 吞吐四方对拍 / 四层内存模型 / FD 治理 / 五万并发 |
| `docs/parity-status.md`（v2.14） | dae↔sodama 分域覆盖度与差异清点 |
| `docs/optimization-roadmap.md`（O1–O10） | 已完成/在途的性能项与验收口径 |
| `docs/phase2-devlog.md` §10/§11 | 生产实战轮的根因与修复语义 |
| `docs/reviews/` | 两份第三方评审及其触发的 I1–I5 改进 |

---

## 0 · 摘要（结论先行）

1. **运行时换代有硬数据**：20 000 并发连接下用户态内存 **30.4 MB vs dae 1 662 MB**
   （净增 0.9 KB/连接 vs ≈82.7 KB/连接）；计入内核侧后**系统总量 ≈1.20 GB vs ≈2.47 GB**；
   线程两方都是 O(核数)，差距在**每连接的缓冲/对象/GC 行为**，不在线程模型本身。
2. **语言无关的「可靠性语义」是 dae 今天就能拿的最大红利**——它们全部来自生产事故
   （探测线程泄漏、入口轮换、订阅截断/限流/半截正文），与语言无关，共 12 条语义，
   见 §2.3 与 §4.1 的移植清单。
3. **Rust × 内核耦合的下一步有明确落点**：eBPF 程序 Rust 化（23 程序/4.4k 行 C →
   8 程序/~1.1k 行 Rust 的等价面）、TCX 生命周期、kTLS+splice+reactor 组合、
   内核侧流控（EDT 令牌桶 + DSCP）、cgroup v2 内存 QoS；路径与判据见 §4.2。
4. **有五个高预期方向被我们实测否决或降级**（io_uring、AES-GCM 优先、UDP 批量、
   kTLS 全场景、『RSS 低=省内存』）——见 §3，建议 dae 直接引用结论、省掉复测。
5. **迁移不是全有或全无**：给出三条并行路线（Go 内回填 / Rust 组件接入 / 全 Rust 终局），
   每阶段带验收门槛（沿用我们的 lab 夹具与判据），见 §4.0/§4.4。

---

## 1 · 坐标：两个实现，一套夹具

### 1.1 dae（Go 上游）现状清点

| 维度 | 现状（`parity-status.md` 清点，dae `main@e3fee8f`） |
|---|---|
| eBPF 数据面 | **23 个程序**（13× TC L2/L3 变体 + sk_skb offload + 5× cgroup + kprobe/fentry）、24 个 map、**4 403 行 C**（clang/cilium-ebpf 工具链） |
| 用户态 | Go：relay（并发上限/backlog fuse/计费）、UDP endpoint pool（full-cone）、offload、订阅/健康/sticky IP |
| 控制台 | daed（独立项目，GraphQL/Web UI） |
| 基线性能（同夹具） | ss 9 357 Mbps / CPU 460 ms；vless 12 689 Mbps；vless-tls 11 453 Mbps；20k 连接 RSS 1 662 MB |

### 1.2 sodama（全 Rust 重写）现状

| 维度 | 现状 |
|---|---|
| eBPF 数据面 | **8 个程序**（7× TC 含单臂 dual-role + sk_skb offload）、14 个 map（BTF）、**~1.1k 行 Rust**；C 已退役；TCX 退出即摘钩 |
| 用户态 | Rust：Reactor 池（每连接 0 线程）、splice 零拷贝、有界缓冲池、独立 DNS 控制面、订阅系统、状态面/面板 |
| 基线性能（同夹具） | ss 9 487 Mbps / CPU 590 ms；vless 12 225 Mbps；vless-tls 11 624 Mbps；20k 连接 RSS **30.4 MB** |
| 覆盖度 | 主链路 ≈95–99%；全功能面按域 65–97%（详见 parity-status） |

### 1.3 同夹具对照总表（四方对拍节选，4 流 × 48 MB）

| 路径 | 指标 | sodama | dae v2.1.1 | 备注 |
|---|---|---|---|---|
| direct | Mbps / p50 / CPU / RSS | 24 319 / 16 µs / 0 ms / 28.6 MB | 24 200 / 16 µs / 0 ms / 54.2 MB | 两者均触夹具环回上限（≈24.5 Gbps），数字是**下界** |
| ss | Mbps / p50 / CPU | 9 487 / 46 µs / **590 ms** | 9 357 / 43 µs / **460 ms** | 加密环路 CPU 我们暂输 28%（O1/O2 在途） |
| vless | Mbps / p50 / CPU | 12 225 / 40 µs / 380 ms | 12 689 / 42 µs / 410 ms | 基本平手 |
| vless-tls | Mbps / p50 / CPU | 11 624 / 46 µs / 420 ms | 11 453 / 55 µs / 450 ms | 平手；p50 略优 |
| 20k 连接 | RSS / 线程 / fd·连接 | 30.4 MB / 28 / 4.0 | 1 662 MB / 26 / 2.0 | **内存是数量级差**；fd 拓扑 dae 更优（2.0） |
| 系统总量 @20k | 用户态+内核 | ≈1.20 GB | ≈2.47 GB | 内核侧是大头（sodama ≈52.5 KB/连接 vs dae ≈34.0 KB/连接） |
| 50k 连接 | 稳定性 | 32.9 MB / 零失败 / 零泄漏 | —（未同口径） | 我们的有界性判据 |

---

## 2 · 我们已经做的（可直接迁移的优化组合）

> 读法：每条给出「做法 → 实测证据 → 对 dae 的可迁移性」。
> 可迁移性三档：**回填**（Go 内可做）/ **伴生**（Rust 组件/并行供给）/ **替换**（需换实现）。

### 2.1 内核数据面：从「C 大而全」到「Rust 精准」

| # | 做法 | 实测证据 | 对 dae |
|---|---|---|---|
| 2.1.1 | **eBPF 程序 Rust 化**（aya + `bpfel-unknown-none` + BTF/CO-RE，共享 ABI `common.rs`） | 23 程序/4 403 行 C → 8 程序/~1.1k 行 Rust（主路径语义逐一对齐）；CI 可构建（固定 nightly + bpf-linker） | **伴生→替换**：按程序族逐批替换，map ABI 用 BTF 保持兼容 |
| 2.1.2 | **域匹配位图**（SodaEpochIp + 预计算索引）替代逐规则字符串匹配 | 域位图重建仅几十毫秒；匹配在 TC 层 O(1)（`bitmap_matched` 计数器在线） | **回填**（dae 已有双 epoch 热重载，位图替换匹配结构） |
| 2.1.3 | **双槽原子切换热重载** | `rules reloaded: N match_sets -> slot X`；重载零丢包、零窗口 | **回填**：dae 语义同源，补「active_slot 回执」到状态面 |
| 2.1.4 | **offload 内核对拼**（sk_skb sockmap 直通 + 用户态零字节 + 看门狗单线程化） | 200 条 offload 连接 **0 新增线程**；offload 成功后用户态不再碰包 | **替换**：dae 已有 offload；我们验证了其生命周期/看门狗简化 |
| 2.1.5 | **redirect_track 泄漏修复**（对照上游 `cleanupRedirectTrackMap` 教训） | 5min TTL + 90% 容量告警 + 单写者；生产 70h+ 无泄漏 | **回填**（若 dae 同结构存在同类风险，直接引人 TTL/告警） |
| 2.1.6 | **pname 采集走 cgroup2**（cookie_pid_map + 规则 VM） | 对照 dae kprobe/fentry 路线；无 kprobe 依赖、硬内核无指纹 | **回填**（语义等价、部署更广） |
| 2.1.7 | **TCX 挂点**（内核 ≥6.6） | 退出即摘钩，无残留 qdisc 状态；lifecycle 简化 | **替换**（需内核矩阵声明） |

### 2.2 用户态运行时：线程模型与内存模型

| # | 做法 | 实测证据 | 对 dae |
|---|---|---|---|
| 2.2.1 | **Reactor 池**：每连接 0 线程（epoll/splice + 全协议 codec 泵） | hold 10k：线程模型 **20 011 线程/763 MB** → **28 线程/32.1 MB**；连接风暴 **25 606/s**（线程模型 20 860/s）；vless-tls 2 000 连接 27 线程/61 MB（线程模型 4 011/222 MB） | **回填**（Go netpoller 已是 epoll；这是 dae 做得好的部分——差距在**每连接状态大小**） |
| 2.2.2 | **splice 零拷贝**（M1） | relay 8 流 14.9→**21.6 Gbps**、CPU 1100→**150 ms**；vless 明文 12.2→**16.9 Gbps**、CPU 380→60 ms | **回填**（dae 已有 splice；我们验证了与 reactor/codec 的接线） |
| 2.2.3 | **有界缓冲池**（64/128 KB 块，按字节封顶 8 MB）+ **主动回收**（30s `malloc_trim`）+ **启动水位**（I6） | churn 300 条无增长；20k→50k 连接 30.4→32.9 MB 近似平坦；空闲常驻 11.9 MB | **回填**（Go 对应物：sync.Pool 深度化 + GOMEMLIMIT；但 GC 下限无法根治） |
| 2.2.4 | **零线程握手**（ADR-0059） | 握手阶段不进线程池；启动/风暴期线程峰值不飘 | **伴生**（Go 的 goroutine 本就轻；重点是**每连接缓冲**不在握手期分配） |
| 2.2.5 | **kTLS 实验**（M2）：内核 TLS + TLS 上 splice | 48MB×4 中位 11.67→**12.32 Gbps**（+5.6%）、CPU 420→400 ms、`memcpy` 占 **29.4%→1.6%** | **伴生**（Go：需换 TLS 栈或 cgo 调 kTLS；风险中，建议参考我们 ADR） |
| 2.2.6 | **Vision-over-TLS（XTLS DIRECT 等价）**（M3） | tls/reality 内层 TLS 逐字节 + 双向 DIRECT；真订阅 48 节点 5MB e2e 6/6 命中 | **替换**（协议侧工作，与语言无关） |

### 2.3 可靠性与运维语义（**语言无关，价值密度最高**）

> 全部来自生产事故复盘（§10/§11），每一条都有「事故 → 根因 → 语义」的完整证据链。

| # | 语义 | 事故/根因 | 对 dae |
|---|---|---|---|
| 2.3.1 | **拨号墙钟看门狗**：建连后到点 `shutdown(fd, SHUT_RDWR)` 硬截断握手 | 553 个探测线程卡死在无超时的 `recvfrom`（20h 累积） | **回填**：Go 用 `time.AfterFunc` + `syscall.Shutdown`（结构同样存在） |
| 2.3.2 | **探测批处理截止线 + straggler 计数 + 线程上限** | `thread::scope` 等全部子线程 → 一个卡死拖垮整轮探测 → 全网零延迟数据 | **回填** |
| 2.3.3 | **sticky IP 拨号重解析**（修正「只作废不重解析」） | 机场入口域名轮换 → 节点永远钉在旧 IP（subA 63 个死 57） | **回填**：检查 dae 的 `StickyIpDialer` 是否也有「解析期固化」形态 |
| 2.3.4 | **订阅正文完整性**：Content-Length 精确校验 / 读超时≠EOF / 无 CL 需换行收尾 | 50 节点被截成 22 却被当「成功」（假节点 `2-22`） | **回填**（校验与异常语义语言无关） |
| 2.3.5 | **拉取重试 ×3 + 截断宽容最后手段** | 截断是概率性的：同一源分钟级内时好时坏；宽容兜底避免「零节点启动」 | **回填** |
| 2.3.6 | **订阅磁盘缓存**（原始正文 0600，失败/重启回退） | 端点 403/429/截断窗口 + 重启 = 丢源 | **回填** |
| 2.3.7 | **周期刷新 + 429 冷却 + 失败源自愈退避**（5min→1h） | 「订阅腐烂」：只在启动拉取，旧列表永不更新 | **回填**（dae 无此物，Clash 有 interval——兼容两者习惯） |
| 2.3.8 | **按源保留成员**（失败源沿用旧成员；删源自然丢弃） | 一个源拉取失败 → 63 个成员被整体清空 | **回填**（替换语义改为 partial-update） |
| 2.3.9 | **reload 与网络拉取解耦**（后台线程 + mpsc 合并 + 回执毫秒级） | 面板等待回执 15/20s，重载实际 19–34s → 「热重载失败」误报 | **回填**（dae 无面板，但**回执语义**对自动化很重要） |
| 2.3.10 | **本地 policy 不随拉取早退** | 「切换节点」写入了 `fixed(...)` 但全源拉取失败时被跳过 → 静默不生效 | **回填** |
| 2.3.11 | **订阅顺序回退（pacman）**：首个有活节点的源生效 | 多源场景常态化；手动重排 = 秒级热驱动 | **扩展**（dae 有 alive set；`subscription_failover` 是我们 P34 扩展） |
| 2.3.12 | **状态面 DTO 化 + 面板分离**（status JSON / Prometheus / 域统计） | 两份第三方评审直接推动了四层内存模型（RSS/slab/总量/每连接） | **回填→生态**：建议 dae 也把状态面做成稳定 DTO（GUI 可复用） |

### 2.4 工程方法论（最被低估的迁移项）

1. **单变量对照**：`SODAMA_NO_REACTOR=1`、`SODAMA_REACTOR_CODEC=0`、`SODAMA_UDP_BATCH=0`
   把「架构假设」变成可复现实验；建议 dae 的每次重构都带开关对照。
2. **现场取证优先于重启**：重启前抓 `/proc/<pid>/task/*/{stack,wchan,syscall}`
   （我们据此定位 553 个线程卡死在 `recvfrom`）；事后重启只能得到「看起来修了」。
3. **四层内存模型**：用户态 RSS ≠ 系统内存；内核侧可以比用户态大 ~30×（本仓报告）。
   任何「省内存」声明都应给出四层口径。
4. **对拍门槛**：规则编译逐字节对拍 5/5（对照 dae）；协议栈对拍（ss/tuic/hy2 跨实现）。
5. **长稳判据**：50k 连接零失败/零泄漏；72h soak（本仓 §12 进行中）；churn 无残留。
6. **踩坑档案化**：atlas「踩坑档案」模式——每条含现象/现场/根因/修复/验收。

---

## 3 · 我们实测否决/降级的五个高预期方向（替 dae 省学费）

> 这些结论比「我们用 X 赢了」更有价值——它们定义了**收益边界**。

| # | 预设 | 实测结果 | 处置 |
|---|---|---|---|
| 3.1 | 「上 io_uring 会更快」 | epoll+splice reactor 已近线速；io_uring 引入的复杂度/收益比不佳（A/B 已做） | **不引入**（保留 revisit 判据：见 §4.2-5） |
| 3.2 | 「AES-GCM 应优先于 ChaCha20」 | 本机 RustCrypto：AES-NI 块加密 ~6 GB/s，但 **GCM 受 GHASH 串行限制**（16KB 块 1.57 vs chacha 1.73 GB/s） | 保留 chacha；vmess auto→chacha；定向换 ring/aws-lc 后端列后续 |
| 3.3 | 「UDP recvmmsg/sendmmsg 批量会显著提速」 | 限速场景下每批 ~1 包（非 syscall-bound） | 实现保留（A/B 开关），**不宣称大幅提升** |
| 3.4 | 「kTLS 全场景白拿」 | 48MB×4 中位 +5.6%；8 流受同机夹具/内核 AES 速度限制 | 作**实验开关**；真实链路收益待复测 |
| 3.5 | 「用户态 RSS 低 = 系统省内存」（第三方评审恰好问了这句） | 内核侧可以≈**30×**于用户态；总量口径 sodama 1.20 GB vs dae 2.47 GB（仍赢，但论据必须换成四层模型） | 对外口径全部改为「用户态+内核」双口径 |

另两个「反向发现」（dae 比我们好的地方，值得学习）：

- **fd 拓扑**：dae **2.0 fd/连接**；我们治理前 8.3（splice 管道结构）→ 治理后 4.0。
  教训：零拷贝原语选型要连同 **fd 拓扑**一起设计（我们的 FD 治理经验已产品化）。
- **ss 用户态加密环路**：同口径 CPU 我们 590 ms vs dae 460 ms（暂输 28%）——
  说明 Go 在**纯内存热循环**上并非天然慢；差距来自分配/拷贝/syscall 频次，O1/O2 在途。

---

## 4 · 现在能做的优化（架构思路与实现路径）

### 4.0 三条路线（建议并行，不串行）

| 路线 | 范围 | 周期量级 | 验收门槛（沿用我们的夹具/判据） |
|---|---|---|---|
| **R0 · Go 内回填** | §2.3 十二条可靠性语义 + 观测 DTO + 内存/FD 纪律 | 周 | 面板/自动化回执 <2s；失败源自愈；无卡死线程；RSS 曲线平台化 |
| **R1 · Rust 伴生** | eBPF 程序族替换、kTLS/offload 组合、relay 侧进程化 | 月 | 规则对拍 5/5；verify 9/9；四方对拍吞吐不退化；20k RSS ≤50 MB |
| **R2 · 全 Rust 终局** | 采用 sodama 现状 + parity 余项收敛 + 打包（backlog A） | 季 | parity 主链路 ≥90%；50k 零失败；72h soak |

### 4.1 R0：Go 内可做（不改架构的确定性收益）

1. **可靠性语义 12 条直接移植**（§2.3 表），关键 Go 对应物：
   - 墙钟看门狗 → `time.AfterFunc` + `syscall.Shutdown(fd, SHUT_RDWR)`；
   - 探测批处理 → `context.WithDeadline` + 放弃后不等待 + straggler 计数；
   - sticky 重解析 → **拨号路径每次过缓存**（不是 dialer 构造期）；
   - 订阅完整性/重试/磁盘缓存/自愈退避 → 按 §2.3.4–2.3.8 逐条落地。
2. **内存纪律（目标：削峰而非根治）**：
   - `GOMEMLIMIT` + `GOGC` 设定；连接对象字段裁剪（参照我们 `Member/NodeSnap` 的瘦身）；
   - 热路径分配清单：`io.Copy` 的 32 KB 缓冲入池；避免 interface 装箱分派；ring 缓冲替代 `bytes.Buffer`；
   - 如实：Go 无法无停顿强制还页（`debug.FreeOSMemory` 有 STW 代价）——**天花板要写进文档**。
3. **FD/管道纪律**：审计 splice 管道 fd；dae 2.0 已是好基线，保持并加容量告警。
4. **状态面标准化**：`subscriptions[]`/`stragglers`/`reload` 回执升级为稳定 DTO + Prometheus 命名。
5. **AI 流低延迟模板**：TCP_NODELAY/立即 flush/热连接池/不聚合缓冲（我们已做成模板可抄）。
6. 打包与发行工程：直接引用 `docs/backlog.md` A 节（Docker/发行包/补全），不重复。

### 4.2 R1：Rust × 内核耦合（我们已铺路，dae 可加速）

1. **eBPF 程序 Rust 化迁移包**（最有确定性的内核收益）：
   - 工具链：aya + 固定日期 nightly + bpf-linker 0.11.1（本仓 CI 已验证可复现）；
   - 迁移策略：按程序族逐批（TC 分流主路径 → offload → cgroup/kprobe 变体淘汰，pname 走 cgroup2 已验证）；
   - **map ABI 共存**：C 与 Rust 程序可临时共享同布局 map（BTF/CO-RE）；
   - 挂点现代化：TCX（内核 ≥6.6）退出即摘钩；
   - 验收：规则编译逐字节对拍 5/5 + lab verify 9/9。
2. **kTLS + splice + reactor 三层组合产品化**：
   - 触发：TLS1.3 且走 TCP relay；旁路：Vision DIRECT / need-sniff / 不支持的 cipher（我们的实测边界）；
   - 对 dae：Go 标准库无 kTLS → cgo/第三方包，或引入 Rust 伴生进程做 TLS 终结（成本中，收益 +5.6% 为同夹具下界）。
3. **内核侧流控与优先级**（新方向，路径已清）：
   - TC eBPF **EDT 令牌桶/fq**：把 dae 的 `bandwidth_max_tx/rx` 从用户态挪进内核（每包节奏、无唤醒）；
   - **DSCP 标记** + CAKE 协同：AI/交互流高优先级（与我们的 AI 模板在规则层合流）；
   - 验收：限速 CPU/p50 对照（同一 lab 夹具）。
4. **内存 QoS 化**：cgroup v2 `memory.high` + PSI 监听——逼近软限时降级（缩缓存/降探测）而非 OOM；与有界缓冲池合流。
5. **io_uring revisit 判据**（而非结论）：当满足任意：① sendmsg_zc 需绕开 splice 中转；② 单核 pps 成为新瓶颈需 SQPOLL；③ 需要 IORING_OP_SPLICE 替代管道——再复测；否则维持 epoll+splice。
6. **CPU/拓扑**：thread-per-core reactor + 每核 arena + SPSC；SO_REUSEPORT 分布 UDP——**仅当核数 ≥4 且 pps 高**时做 A/B（我们 2 核路由器场景无收益）。
7. **观测双向补全**：sodama 补 dae 已有的 **ringbuf/kprobe**（per-conn 事件流）；dae 学我们的计数器布局/Prometheus 口径/域统计。

### 4.3 R2 与生态创新

- **控制面契约**：status DTO 版本化（我们与面板已实践）；建议 dae 把 reload 做成
  `started/completed` 双事件回执（自动化依赖它）。
- **规则/订阅互操作**：我们已支持 Clash rule-provider YAML / sing-box rule-set JSON——
  dae 回填后，分流规则生态工具可双向复用。
- **面板生态**：我们的 36 项参数可视化 / 回执语义 / 曲线十字光标经验，可直接给 daed 参考。
- **供应链韧性套件**作为发行标配（P34 顺序回退 / P35 热驱动 / §11 完整性自愈）。
- **安全基线**：见 `docs/security-proposal.md`（S0–S5），本档不重复。

### 4.4 建议排期

| 优先级 | 项目 | 路线 | 预期收益 | 成本 |
|---|---|---|---|---|
| P0 | §2.3 十二条可靠性语义 | R0 | 生产事故类问题一次性清零 | 周 |
| P0 | eBPF Rust 化迁移包（TC 主路径） | R1 | 工具链现代化 + verifier 友好 + 共享 ABI | 月 |
| P1 | 状态面 DTO + 内存/FD 纪律 | R0 | 可观测性 + 削峰 | 周 |
| P1 | kTLS 组合产品化（带旁路表） | R1 | TLS 段 splice 可用（+5.6% 下界） | 月 |
| P1 | 内核流控 EDT/DSCP | R1 | 用户态限速零唤醒 + AI 流优先 | 月 |
| P2 | 内存 QoS（cgroup/PSI） | R1 | OOM 前降级 | 月 |
| P2 | 内存 QoS（cgroup/PSI） | R1 | OOM 前降级 | 月 |
| P2 | R2 全 Rust 采用 + 打包 | R2 | 终极形态（按需启动） | 季 |

---

## 5 · 风险与边界（如实）

1. **Go 内回填的天花板**：R0 能拿到可靠性/观测/削峰，但拿不到
   每连接 0.9 KB 的净增内存与无 GC 尾延迟——这是运行时性质，不是代码风格问题。
2. **C→Rust eBPF 迁移的可逆性**：建议逐程序族替换且保留回退路径（双挂不可行时以
   map ABI 兼容窗口过渡）；每批替换必须有对拍+验证门槛。
3. **内核版本矩阵**：TCX（≥6.6）、kTLS（TLS1.3+modprobe tls）、cgroup2 钩子、
   BPF 特性各有下限——发布需要声明矩阵（我们 `docs/openwrt.md` 的 fragment 方法可复用）。
4. **双栈维护成本**：R1 期间 C/Go/Rust 三栈共存——务必限定替换顺序与回收时点，避免长期三栈。
5. **测量陷阱**：本档所有吞吐数字均受**同机夹具环回上限（≈24.5 Gbps）**约束；
   异地链路下的绝对值需重新标定（我们的 72h 生产测试在本档写作时进行中）。
6. **收益递减点**：我们的数据表明 30–40 MB / 28 线程已接近「够用即最优」——
   继续优化应转向**延迟分布（p99/TTFT）与可预测性**，而不是继续刷 RSS/吞吐。

---

## 附录 · 证据索引

| 结论 | 证据文件 |
|---|---|
| 四方吞吐/五万并发/四层内存/FD 治理 | `docs/benchmark-report.html`（v3.0）·`docs/memory-report-v2.html` |
| M1 splice / M4 reactor / kTLS / Vision 实测数 | `docs/optimization-roadmap.md` O3/O4/O9/O10 · ADR-0058/0057/0059 |
| dae↔sodama 分域覆盖度与差异 | `docs/parity-status.md`（v2.14） |
| 可靠性语义十二条的完整事故链 | `docs/phase2-devlog.md` §10 / §11（含 §11.7 实施与验收） |
| 第三方评审与采纳 | `docs/reviews/` |
| OpenWrt/内核依赖矩阵 | `docs/openwrt.md` · `docs/deploy.md` |
| 安全基线 | `docs/security-proposal.md` |
| 本项目自身优化在途项（O1/O2 等） | `docs/optimization-roadmap.md` |
| 工程化/发行余项 | `docs/backlog.md` A 节 |

> 维护约定：本文档随每次「对 dae 有可迁移价值」的实测更新——新增结论必须带
> 「做法/证据/可迁移性」三要素，负面结论同等收录。
