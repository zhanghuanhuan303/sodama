# ADR-0021：P6 运维面——信号/控制命令、指标导出、日志与整配置热重载

- **状态**：已采纳（2026-10-03）
- **对应**：路线图 P6（reload/suspend/sysdump/trace/日志轮转/统计导出；daed API 兼容层视需要）
- **相关**：ADR-0011（状态面原为只读）、ADR-0009（内核先行）、ADR-0015（relay/offload 计数来源）

## 背景

dae 的运维面由 cmd 子命令 + 信号组成：`dae reload [pid]`（SIGHUP + progress 文件 + 超时/回滚，
`cmd/reload.go`）、`dae suspend [pid]`（SIGUSR2 → no-load，`dae reload` 恢复，`cmd/suspend.go`）、
`dae sysdump`（系统网络信息归档，`cmd/sysdump.go`）、`dae trace`（运行时跟踪）、`dae validate` 等；
监控侧 daed 提供 GraphQL，**dae 本体没有 Prometheus 导出**（源码实测：无 metrics 目录/prometheus 依赖）。
sodama 的 K3 状态面此前是**只读**的（status/rules/config/maps），没有控制路径、没有日志文件、
没有统计导出格式；SIGHUP 只重编译规则文本，`--config` 模式不重读 dns 段。

## 决策

1. **信号面**（对照 dae cmd）：
   - `SIGHUP` = reload：重读 `--rules`/`--config` → 编译 → 非活跃槽 → 切换；**同时清除 suspend**
     并 reopen `--log-file`（对照「dae suspend 后用 dae reload 恢复」）；
   - `SIGUSR2` = suspend：主循环写 eBPF `control_flags_map`（新增，ARRAY u32×1）的 bit0；
     C 侧 5 个分流入口读到该位即 `TC_ACT_OK`（**no-load / fail-open**，内核直转）。
2. **状态面从只读扩展为「查询 + 控制」**（`loader/src/status.rs`）：
   - 查询：`status|rules|config|maps|metrics`；控制：`reload|suspend|resume`；
   - 控制命令与 DNS 的 `DnsPublish` 一样经 mpsc 交**主循环串行执行**（唯一持有 `Ebpf` 的地方），
     因此不引入并发写 map 的问题；
   - 响应协议从「单行」改为「读到 EOF」（metrics 是多行文本）。
3. **CLI 子命令**（`sodama …`）：`reload`（等价 SIGHUP，同步等结果，失败退出码非零）、
   `suspend`/`resume`、`metrics`、`sysdump`（状态+规则+配置+maps+系统网络信息 → JSON）、
   `trace --seconds N`（过滤 sodama 的 ftrace `trace_pipe`）。
4. **指标导出（Prometheus 文本）**：`metrics` 命令把 status JSON 扁平化为 `sodama_*` 序列
   （relay/udp_nat/dns/maps/stats/uptime/suspended/reload_success + `sodama_info{dialer=…}`）；
   dae 本体无 Prometheus，daed GraphQL **不做**（边界，见第 7 条）。
5. **日志**：新增 `--log-file <path>`（默认 stdout），所有日志经同一 sink；
   SIGHUP 时 reopen（不经 systemd 的 logrotate 友好形态）；不实现日志分级（dae 有 log_level，
   见边界）。
6. **整配置热重载与回滚**：`--config` 模式下 reload 完整重跑 include/parse/schema/子集编译；
   编译失败时 `reload_rules` 不切槽（**等价回滚**，旧规则继续服务），状态面 `reload.ok=false`
   并带错误文本；`--strict-config` 在重载时同样生效；`dns.upstream` 变更会在规则重载成功后
   **热切换**（`UPSTREAM_ADDR` 由 OnceLock 改为 Mutex，DNS 线程每条查询读取当前值；
   `--dns-upstream` 显式给定时不覆盖）。
7. **明确不做**：daed GraphQL/鉴权 API；`suspend --abort`（不主动断开已建立连接，只停新判决）；
   systemd unit/打包；日志分级与多后端；trace 只做 ftrace 过滤（不是 dae 的运行时跟踪全功能）。

## 理由

- dae 的 reload/suspend 本质是「信号 + 数据面状态位」：sodama 沿用同一形态（SIGHUP/SIGUSR2 +
  eBPF 控制位），并把同一动作暴露到状态面/CLI，便于测试与编排（dae 靠 pid 文件与 progress 文件，
  sodama 不需要进程间文件协议）；
- suspend 用 eBPF 标志位而不是摘钩子：摘/挂 TCX 钩子有窗口期与失败面，标志位是一个原子 map 写入，
  语义是「全部流量直线放行」，与 dae 的 no-load 等价且可被 reload 瞬间恢复；
- 指标选择 Prometheus 文本是因为它是运维事实标准，且实现只依赖已有状态数据（无新依赖）；
  daed 的 GraphQL 是另一套（鉴权/订阅/写接口），在 sodama 范围外，如实标注；
- 整配置热重载以「编译失败不切槽」实现回滚：与现有双 epoch 机制天然一致（非活跃槽写坏也不影响
  活跃槽），无需额外快照。

## 后果

- 正面：运维面从只读升级为可控（reload/suspend/resume）+ 可观测（metrics/sysdump/trace）；
  `--log-file` 支持 logrotate 式轮转；`--config` 模式支持在线改规则/DNS 上游而不断流；
  所有控制路径都过主循环，eBPF 并发语义不变。
- 负面/代价：状态面不再是只读面（文档与 ADR-0011 需注明扩展）；suspend 是 fail-open 语义，
  不等价于「断开」（无 --abort）；控制命令依赖状态面 socket 存在（无 socket 时 CLI 报连接错误）。
- 风险：suspend 期间已建立的 relay/UDP NAT 会话仍由用户态线程继续服务（与 dae no-load 相同）；
  reload 期间新连接可能落在旧槽（双 epoch 语义，与 K1 一致）。

## 验证方式（实测）

- lab `test-ops`（`ops-up` 会话）：suspend 后客户端探测从 tproxy 变为内核直转（fail-open）、
  状态面 `suspended=true`；`reload` 后恢复 tproxy、`active_slot` 切槽、`suspended=false`、
  `reload.ok=true`；`metrics` 输出 42 行 `sodama_*`；`sysdump` 六键 JSON 可解析；
  `--log-file` 经 `mv + SIGHUP` 后新文件重建且含重载记录。
- lab `test-config-reload`（`ops-reload-up` 会话，/tmp 配置副本）：改 routing 后 reload 生效
  （8080 由 proxy 变 direct）；写坏配置 reload 失败且**旧规则保留**；`dns.upstream` 5353→59999
  后状态面显示新上游且解析失败，切回后解析恢复（`cache.test` → 10.9.10.9）。
- 回归：标准/单臂 verify 9/9、DNS 六专项、relay/offload/UDP 五专项、G1/G2/G3a/G3b（含 obfs/
  brutal/hop）专项、`cargo test` 73/73、`lab/parity.sh`、`lab/proto-check`。

## 修订条件

若要 daed GraphQL 兼容层、`suspend --abort`、日志分级/systemd 集成或 OTLP 等其他导出格式，
另写 ADR 取代对应子条；若 quinn/eBPF 生命周期管理出现更直接的挂起原语（如 TCX 的 pause），
可评估用原语替代控制位。
