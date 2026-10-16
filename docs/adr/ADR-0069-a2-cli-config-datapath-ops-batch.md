# ADR-0069：A2 批次——CLI/配置生效面/DNS/观测/数据面/服务化（除工程打包）19 项落地

- **状态**：已采纳（2026-10-16）
- **对应**：用户决策「完成 a2 除了工程打包的」——`docs/capability-gap-review.md`
  **附 A · A2 部分（26 项）** 中剔除 7 项工程打包（#19 安装升级回滚 / #20 多发行版教程 /
  #21 迁移指南 / #23 内核矩阵入 CI / #24 CI 容器流水线 / #25 72h soak / #26 供应链审计）后
  的 **19 项**（#1–#18 + #22）全部落地；分五批提交（`21fe9a4`/`2a48782`/`0518d57`/`26a0411`/`e5db7fd`）
- **相关**：ADR-0068（A1 批次）、ADR-0066/0067（能力缺口/eBPF 余项）、ADR-0065（offload 记账）、
  `docs/phase2-devlog.md` §23（本批次记录）

## 背景

A2 口径是「能力在，语义/覆盖/形态不完整」的 26 项。剔除工程打包 7 项后，19 项横跨
CLI（`--version` / 日志轮转三参 / `trace` 过滤器 / `sysdump` 现场 / `export outline`）、
配置生效面（global 键 27 → 36 生效）、DNS 语义（`ipversion_prefer` 偏好等待 / 投影重试堆）、
观测（1h 流量历史 / 告警节流 / `real_domain` 状态）、控制面（drain 预算 / `real_domain_runtime` /
钩子生命周期 / sysctl 纠正）、数据面（UDP GSO）与服务化（systemd 单元强化 / `sd_notify`）。
按五批收口，全部并入既有模块，不引入新形态。

## 决策（按批次）

### 批次 1（`21fe9a4`）：CLI 五件套 + 日志分级

- **`--version`**（`main.rs::print_version` + `loader/build.rs`）：三行格式（版本+git sha /
  运行时+平台 / 许可），sha 与 profile 由 build.rs 尽力注入（无 git 时 `unknown`）；
  在子命令分派前处理，无需 root。
- **`export outline`**（`run_subcommand` 的 `outline` 分支）：导出 `key_docs()` 登记表
  的机器可读 schema（与 `config-doc` 同源），供外部工具消费。
- **`trace` 过滤器**（数据面 `trace_filter_map` + `SodaTraceFilter`（`ebpf-rs/src/common.rs`）+
  `flow.rs::trace_verdict`）：4 个判决点（block/direct/存活门禁/redirect）发
  `SODAMA_EVENT_TRACE`（判决在 `SodaEvent.pad[0]`：`VERDICT_OK/SHOT/REDIR`）；过滤在
  **内核侧**（协议/端口/IP 版本/drop-only 位图）先裁、CLI 侧再按条件过滤；daemon 侧
  落盘 `/run/sodama-trace.log`（不可写时退 `/tmp`）。
- **`sysdump --out *.tar.gz`**（新 `loader/src/dump.rs`）：自实现 ustar + **stored gzip**
  （不引入压缩依赖）；打包状态面 JSON、路由表、网卡、sysctl、nft/iptables、日志尾部与
  version.txt 等现场；`tar xzf` 实测可解。
- **日志轮转三参**（`--logfile` / `--logfile-maxsize` / `--logfile-maxbackups`）+
  **`log_level`**（新 `log_warn` / `log_debug` / `log_at`，级别 0=off..4=debug；非法值回落
  info 并告警——对照 dae logrus.ParseLevel 语义）。

### 批次 2（`2a48782`）：global 生效面 8 项 + sysctl 纠正

- **`so_mark_from_dae`**：控制面自身 socket 的 SO_MARK 全链可配；`SodaConfig` 两侧
  （`main.rs` 镜像 + `ebpf-rs/src/common.rs`）同批加 `so_mark` 字段，数据面
  `progs.rs::dae_socket` 改读 config_map（缺配置回落编译期默认 0x233）。
- **`mptcp`**：TCP 出站拨号按开关使用 `IPPROTO_MPTCP`（内核不支持时回落 TCP 并告警）。
- **`allow_insecure`** 全局默认：9 个出站解析点统一接受（节点级显式值优先）。
- **`udphop_interval`** 全局默认：节点未写 `udphop-interval=` 时的全局步长。
- **`fallback_resolver`**（`sticky.rs::resolve_ips` 链：bootstrap → fallback → 系统解析）。
- **`disable_thp`**：启动即 `PR_SET_THP_DISABLE`（只影响本进程，不改系统策略）。
- **`disable_waiting_network`** + 启动等待网络（`wait_for_network`：默认开、上限 30s、
  2s 轮询；判定 = 默认路由存在且 DNS 探针可解析；超时只告警不阻断——对照 dae
  `waitForNetworkOnline`）。
- **`auto_config_kernel_parameter`**（新 `loader/src/sysctl.rs`）：写 `ip_forward` /
  `forwarding` / `send_redirects` / `accept_ra`**并登记期望值**；inotify 监听（降级 2s 轮询），
  **运行中被改回即纠正**（对照 dae SetForwarding/SetSendRedirects）。

### 批次 3（`0518d57`）：DNS 语义 + 观测

- **`dns.ipversion_prefer` 50ms 偏好等待**（新 `loader/src/dns_pref_wait.rs`）：非首选族
  查询在**缓存未命中、即将上行**时登记 50ms 等待；首选族答案到达即取消。缓存命中路径
  不登记（初版曾登记导致未消费条目，已修）。
- **DNS 投影重试堆**（`publish_enqueue_retry` / `publish_retry_tick`）：投影写入失败时
  退避重试（100ms→1.6s、5 次、队列 4096），status 增 `domain_publish_retries/dropped`。
- **1h 流量历史**（`traffic_history_loop` 1s 采样）：status `traffic` 段（ring）+ 2 个 metrics。
- **告警节流 `AlertPacer`**：持续条件 + 冷却窗口（接入 redirect_track、conn_state 容量告警）。

### 批次 4（`26a0411`）：服务化 + 用例

- **`sd_notify`**：READY（就绪）/ RELOADING / STOPPING；无 `NOTIFY_SOCKET` 时 no-op。
- **systemd 单元强化**（`install/sodama.service`）：`Type=notify` / `ExecStartPre` validate
  门禁 / `StartLimitBurst=300`+`5s` / `OOMScoreAdjust=-100` / `Restart=on-abnormal` /
  `TimeoutStartSec=120`+`TimeoutStopSec=30` / `LimitNPROC`。
- **钩子生命周期用例**（`lab.sh test-hooks`）：reload（切代）前后 hooks 集合不变（单进程
  形态：钩子常驻、无跨代交接/无重复挂载——把 ADR-0065 的「形态消解」结论变成可检验断言）。

### 批次 5（`e5db7fd`）：数据面 + 配置余项 + lab 基建修复

- **drain 预算**（`count_sessions` / `drain_old_generation`）：`reload/suspend|resume --drain=N`
  等旧代在飞会话自然排空的预算（超预算**不强制关闭**，如实回报余量与耗时；对照 dae
  `control_plane_drain.go` 语义）。
- **`real_domain_runtime`**（新 `loader/src/real_domain.rs`）：域名确认集（FIFO 8192 + 负缓存
  300s + 单飞近似）+ `dns.rs::has_fresh_any_scope`（不限定 ECS 作用域，对照 dae
  `HasDnsKnowledge`）；`dial_mode=domain` 时 DNS 已知的域名交节点远端解析；status
  `real_domain` 段。
- **UDP GSO**（`udp_gso_enable` / `send_gso_udp`）：`UDP_SEGMENT` cmsg（≤64 段）；EMGSIZE/
  EINVAL/EOPNOTSUPP 回落逐包发送；status 增 `gso_sends/gso_datagrams/gso_unsupported`。
- **`tls_fragment`/`tls_fragment_interval`**（`tls13.rs::configure_fragment`）：CH 按字节区间
  分片（默认 50–100）+ 毫秒区间间隔（默认 10–20），TLS 允许跨记录——仅**自实现 TLS 路径**
  （REALITY/自实现 TLS1.3）生效。
- **`pprof_port`**（`diag_port_loop`）：`127.0.0.1:<port>` 诊断端口（`/` 文本摘要、
  `/json` 结构化）；Rust 无 Go pprof 等价——定位为诊断/取数端口而非火焰图。
- **`utls_imitate` / `tls_implementation`**：接受 chrome/utls 口径（对照 dae 默认
  uTLS Firefox；sodama 自实现指纹为 Chrome-120，见偏离 4）。
- **`bandwidth_max_tx/rx`**（`RateLimiter` 令牌桶 + `parse_bandwidth`）：进程级单例限额
  （`100`=100 Mbit/s、`10mbps`/`1g`/`8192b` 等口径）；`set_rate` 支持 reload 热更新；
  **限额生效时 relay 新连接走拷贝泵**（splice 零拷贝无法在用户态节流）。

### lab 基建修复（批次 5 内，矩阵运行暴露）

- **就绪等待 20s → 50s**（`lab.sh up()/dual_up()`）：启动路径 `wait_for_network` 上限
  30s（无外网/隔离环境等满属设计行为），20s 预算让用例在 daemon 未就绪窗口里跑——
  首轮矩阵 `verify` 8/12 FAIL、`cap` 全部 FAIL 均因此（`direct`/`block` 的 PASS 是无钩子
  时的内核直转假象，更具迷惑性）。
- **`--config` 文件权限幂等收紧 ≤0640**：`dnsbind.dae` 被 git 操作按 umask 重建为 0644 →
  `config::load` 校验拒绝（P38 用例由此假失败）；`up()` 里只收不放地 chmod 640。
- **配置加载失败带首条诊断详情**（`diag_summary`）：原只报「N 项诊断」，本轮定因需另跑
  `validate`。

## 理由

- 19 项里 CLI 五件套与数据面两项（GSO/drain）是「dae 有、sodama 缺」的直接对齐；
  global 生效面 13 项是「解析了不生效」的语义闭合（配置写了就该有效）；其余是观测/服务化
  基线的常规补齐。全部落在既有模块，无架构级新形态。
- 分五批是因为数据面 ABI（`SodaConfig` 加 `so_mark`、`trace_filter_map`）要求
  **loader 与 eBPF 对象同批升级**，批次内自洽可测。

## 后果（正/负）

**正**

- 附 A · A2 部分 26 → **剩余 7**（全部工程打包类）；global 生效面 27 → **36**
  （不生效 18 → 9，余项均有显式告警或 ADR 记录）。
- CLI 具备版本/取证/过滤/归档四件套；systemd 下 Type=notify + 门禁 + 熔断可用了。
- 内核级：`verify` 12/12（QEMU 7.2.8）+ `cap` 12/12（新增 `test-hooks`）；单测
  329 → **346 + 3（ebpf-logic）**。

**负 / 代价**

- `bandwidth_max_*` 生效时 relay 新连接退出 splice 零拷贝（性能换限额；见偏离 3）；
- `tls_fragment*` 仅自实现 TLS 路径生效（rustls 出站分片不了；见偏离 2）；
- `wait_for_network` 在无外网环境每次启动白等 30s（对齐 dae 语义；可配
  `disable_waiting_network: true` 跳过；见偏离 6）；
- `trace` 复用一个事件通道（非独立 tracepoint 程序），高频判决下事件环可能丢尾帧。

## 对 dae 的偏离清单

| # | 偏离 | 理由 | 证据分级 |
|---|---|---|---|
| 1 | `trace` 复用 `SODAMA_EVENT_TRACE` 单一事件通道 + 内核侧位图过滤，而非 dae 的独立 tracepoint/程序 | 复用既有 ringbuf 通道与加载器，避免每判决点多一程序；过滤位图把开销压到近零 | 实测（`trace_line_stream_filter` 单测 + 矩阵运行） |
| 2 | `tls_fragment*` 仅自实现 TLS 路径（REALITY/自实现 TLS1.3）生效；rustls 出站不分片 | rustls 不暴露 CH 记录边界控制；自实现路径已能覆盖 REALITY 主用例 | 代码路径（`tls13.rs::fragment_config` 唯一消费点） |
| 3 | `bandwidth_max_*` 限额生效时 relay 新连接强制拷贝泵；已建立的 splice 连接不受 reload 后新限额影响 | splice 在用户态不可节流；限速按「新连接生效」是可控偏离 | 实测（`rate_limiter_throttles_small_writes` + `splice` 判定短路） |
| 4 | `utls_imitate`/`tls_implementation` 仅接受 chrome 口径（dae 默认 Firefox 指纹） | sodama 自实现指纹即 Chrome-120；其他口径无对应实现，接受值但按 chrome 生效 | 代码路径（`INERT_KEYS` 清空后 2 键转入生效面） |
| 5 | `pprof_port` 是 127.0.0.1 诊断端口（文本/JSON 摘要），非 Go pprof 火焰图 | Rust 无 Go runtime pprof 等价物；端口语义保留（本机、只读） | 实测（`diag_port_loop` 响应 `/` 与 `/json`） |
| 6 | `wait_for_network` 为 30s 上限 + 2s 轮询（无网络事件源）；无外网环境等满 30s | 对照 dae `waitForNetworkOnline` 语义；netlink 事件源留后续批次 | 实测（VM 矩阵归因：`等待网络超时（30.03s，16 次探测）`） |
| 7 | `mptcp` 仅 TCP 拨号路径（UDP QUIC 系不受影响） | MPTCP 是 TCP 层特性；UDP 无对应物 | 代码路径（`outbound` TCP dial 单点） |
| 8 | `sd_notify` 在无 systemd（无 `NOTIFY_SOCKET`）时静默 no-op | 对照 sd_notify(3) 语义（无 socket 即无操作）；避免非 systemd 环境噪声 | 代码路径（`notify` 包装在 env 判定后） |
| 9 | `real_domain_runtime` 的单飞是「近似」（FIFO 确认集 + 负缓存，无跨线程 in-flight 去重） | 目的（域名是否已知）不因重复查询而错；去重只为省调用，近似实现可观测等价 | 代码路径 + 3 单测（`real_domain.rs::tests`） |
| 10 | `trace` 落盘默认 `/run/sodama-trace.log`，不可写退 `/tmp/sodama-trace.log` | /run 是系统规范位置；容器/无 root 场景退 /tmp 保可用 | 代码路径（`sysdump`/`trace` 共用落盘助手） |

工程备注（非 dae 偏离，写给后续开发）：

- 单测里的**进程级全局注册表**（`OUTBOUND_CONNECTIVITY` / `LOG_PATH` / `dns_pref_wait` 队列 /
  `real_domain` 确认集）**跨测试共享且并行**——断言只用自己的 Entry/路径身份，勿断总数。
- 批次 2 起 **loader 与 eBPF 对象必须同批升级**（`SodaConfig`/`trace_filter_map` 是 ABI）；
  旧 loader + 新对象会报「对象不含 trace_filter_map」。
- `offload=FAIL` 在 QEMU 是**既有抖动**（devlog §19；本轮三轮均「连接不通」，与 18:12 基线
  同形态），`vm-init.sh` 已列为信息项，勿当回归。
