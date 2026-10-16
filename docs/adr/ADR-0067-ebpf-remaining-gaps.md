# ADR-0067：eBPF 余项批次——`lan_egress` 角色 · 出口连通性判定 · offload 背压 fuse · 首包 handoff · stats/事件键域对齐 · conn_state pinning

- **状态**：已采纳（2026-10-16）
- **对应**：用户决策「把 ebpf 缺项全部补上」——`docs/capability-gap-review.md` §3 数据面
  全部「未做 / 部分」项的收官（本批后 §3 判定 24 行全部「已完成」，见该文档 v1.2 汇总）
- **相关**：ADR-0012（域位图）、ADR-0043（组分派）、ADR-0065（数据面对标批次）、
  ADR-0066（must/容量批次）、`docs/phase2-devlog.md` §21（本批次记录）

## 背景

`docs/capability-gap-review.md` §3（数据面）在 ADR-0065/0066 之后仍有 4 项「未做」与 6 项「部分」：

1. **未做：`lan_egress` 角色**（L2/L3）——dae 在每个 LAN 接口同时挂 ingress + egress，
   egress 侧做反向 conntrack 刷新（容器/独立 netns 出口场景；`kern/tproxy.c:2771-2855`；
   挂载 `control_plane_core_bind.go:259-280`）。
2. **未做：出口存活判定**——`outbound_connectivity_map`（1536 = 256×3×2，`tproxy.c:116`）+
   `wan_outbound_is_alive`（`:3418-3450`）+ 三处判定（LAN ingress `:3169`、WAN egress TCP
   `:3605`、WAN egress UDP `:3758`）+ `send_blocked_alive_event`（`:820-834`，per-outbound 限速）；
   Go 侧健康投影 `control/connectivity.go`（dial_mode=ip 且策略非 random/fixed 才投影）。
3. **未做：offload 背压 fuse**——`tcp_offload_pause`（`tproxy.c:262-274`：键在 = verdict
   `SK_PASS`、不拆 psock，让用户态泵转发、内核继续排空 retry 队列）+ Go 侧 `fuseStep`
   （`tcp_offload_linux.go:371-460`：backlog = 接收字节增量 −（内核推送 + 用户态泵）；
   超 64 MiB engage / 回落到 1 MiB 且 drain 完成后 lift / drain 上限 10s）。
4. **未做：`conn_state_map` pinning**——dae `LIBBPF_PIN_BY_NAME`（`tproxy.c:530-537`，
   「Loader may override pinning on cold start」），重启后既有流状态保留。

5. **部分：事件类型 3/5/9**——`BLOCKED_ALIVE`（出口不存活阻断）、`SYN_REBIND_REJECTED`（纯 SYN
   拒改活跃流路由）、`SYN_REBIND_REROUTED`（跨代次重路由）；对照 `__mark_tcp_seen`
   （`tproxy.c:2591-2621`）与 `conn_state.{routing_epoch_slot, datapath_generation}`（`:3110-3124`）。
6. **部分：事件限速键域**——dae 权威键域（`control/event_rate_contract.go`）：
   0..255 = per-outbound（BLOCKED_ALIVE 用）、256 blocked / 257 redirect_rebind / 258 overflow /
   259 syn_rebind / 260 stateless_tcp / 261 frag_tail（容量 262）。
7. **部分：`conn_state_map` 容量可配**——`bpf_conn_state_map_size`（dae 默认 262144，
   `config.go:62`；sodama 固定 65536）。
8. **部分：`bpf_stats_map` 缺 6 键**——`REDIRECT_OVERFLOW` / `SYN_REBIND_REJECTED` /
   `STATELESS_TCP_PASSTHROUGH` / `FRAG_TAIL_PASSED` / `PARSE_UNSUPPORTED_L4` / `UNSOLICITED_UDP_SEEN`
   （dae `enum bpf_stats_key` 0..12，`tproxy.c:540-600`）。
9. **部分：`routing_handoff_map` 兜底**——首包交接（`tproxy.c:292-295` 定义、`:3618/:3771/:2890` 写），
   Go 侧读取优先序 conn_state → handoff（`control/utils.go:64-80`）。
10. **部分：`tcp_offload_sent` per-key 背压 fuse**——同 3。

## 决策

### 1. `lan_egress` 角色（新 2 程序）

- 新增 `sodama_lan_egress` / `sodama_lan_egress_l3`（`progs.rs`）：parse → 反向 conntrack 刷新
  （复用 `refresh_reverse_state`），恒 `TC_ACT_OK`。
- 挂载：`attach_role` 的 `Role::Lan` 分支在 ingress 之外**同时**挂 egress（对照 dae
  `setupLanInterface` 双钩子），L2/L3 按 arphrd 判定（既有 `--link-hdr auto` 逻辑）。

### 2. 出口连通性判定

- 数据面：新 map `outbound_connectivity_map`（`Array<u32,1536>`）；`outbound_is_alive`
  （`flow.rs`）：保留 outbound（≥0xFC）与 dport 53 放行，其余按 `outbound*6 + domain*2 + ipver`
  读表（0 = 不存活）；判定点 = 本轮新出路由的非 direct/block 判决（对齐 dae 三处调用的合并语义）；
  不存活 → `send_blocked_alive_event`（限速键 = outbound 本身，0..255 键域）+ `TC_ACT_SHOT`。
- 控制面：`publish_outbound_connectivity`（`main.rs`，2s tick 循环）：`dial_mode=ip` 且策略非
  random/fixed **且组非空**时投影真实健康（组内 any alive），否则恒 1。**空组不投影**是 sodama
  特有形态的防护（sodama 的组可为空节点 + dialer 兜底；投影 0 会阻断兜底流量）。
- 状态面：`maps.connectivity_dead_groups` + `stats.blocked_alive` 事件计数。

### 3. offload 背压 fuse

- 数据面：新 map `tcp_offload_pause`（`LruHashMap<SodaTuple, u8, 8192>`）；verdict 命中键 → `SK_PASS`
  （`offload.rs`；fast_sock 条目保留，内核继续排空）+ `offload_pause_passes` 计数键（sodama 自有）。
- 控制面（`main.rs`）：
  - **注册时清残余 pause 键**（对照 dae `tcp_offload_linux.go:306-333`）；
  - 看门狗每轮 `offload_fuse_step`：backlog = 两侧 `TCP_INFO.tcpi_bytes_received` 增量 −
    （`offload_sent` 只读求和 + 用户态泵字节）；判定抽成纯函数 `fuse_decision`（单测锁定）；
  - **两阶段 lift**（本批修的真实死锁）：backlog 回落（或 engage 超时）→ `DrainStart`
    （置 stop、泵排空两侧到无数据）→ `Lift`（删 pause 键）；drain 超时 → `LiftTimeout`
    （强制 lift + 告警）。**不能**直接 lift：接收队列里残余的 SK_PASS 数据与恢复后的内核
    拼接路径乱序（对照 dae `drainResidual` 前置）；
  - 泵：每会话一线程（poll 两 fd + 读干转发；fuse 期间才有，非常态）；
  - 阈值 `SODAMA_FUSE_MAX_BACKLOG` 可覆盖（默认 64 MiB；测试用）。
- 状态面：`offload_fuse.{engages,lifts,failures,threshold,pause_passes}`。

### 4. `conn_state_map` 容量与 pinning

- 容量：`bpf_conn_state_map_size`（global 键，默认 262144 = dae 默认）→
  `EbpfLoader::set_max_entries("conn_state_map", n)`，**启动时生效**；越界（<1024 / >4M）忽略用默认。
- pinning：加载后 pin 到 `/sys/fs/bpf/sodama/conn_state_map`；**冷启动迁移**——若 pin 文件存在，
  打开旧表、把条目搬迁进新表、摘旧 pin、pin 新表（尽力而为，失败只告警）。旧条目的
  `datapath_generation` 必与新进程不同 → 纯 SYN 按「异代重路由」处理（语义正确）。

### 5. 纯 SYN 重绑（事件 5/9 + stats 5/12）

- `SodaConnState` 增 `routing_epoch_slot: u8` + `datapath_generation: u16`（loader 镜像同步）；
  `datapath_generation` 由 loader 维护（启动随机非 0、**reload 递增**），写入 `config_map`。
- `split_flow` 的纯 SYN（新流 && cached 条目 has_routing）：
  - 同代（slot 编码 + generation 均匹配）→ **拒改**：保留条目、`SYN_REBIND_REJECTED`（stats 5 + 事件 5）；
  - 异代 → 删条目 + 本轮重路由（`REBIND_REROUTED`，stats 12 + 事件 9）。
- 限速键 259（`SODAMA_EVENT_RATE_SYN_REBIND`）。

### 6. 首包 handoff

- 数据面：新 map `routing_handoff_map`（`HashMap<_, 65536, NO_PREALLOC>`）+ `handoff_scratch_map`
  （per-CPU 暂存，见「后果」的栈限）；首包重定向时写（TCP 纯 SYN；UDP 无 state 的新流），
  内容 = 路由结果位编码 + dscp + mac + generation。
- 控制面：`lookup_conn_outbound` 改为「conn_state（has_routing）→ miss 再读 handoff
  （`SODAMA_HANDOFF_TTL_NS` = 30s 陈旧上限）」，对照 dae `RetrieveRoutingResult`。
- 状态面：`maps.routing_handoff` 计数。

### 7. stats 键域对齐 dae（0..12）

- `sodama_stats_map` 重排为 dae `enum bpf_stats_key` 0..12：0/1 UDP/TCP conn 溢出（拆键）、
  2 redirect 表满、3 redirect 更新失败、4 redirect 重绑拒斥（原键 0）、5 SYN 重绑拒斥、
  6 无状态 TCP 直通、7 分片尾直通、8 L4 不支持、9 无主 WAN-ingress UDP、10 SOCKMARK 占位
  （sodama 无 so_mark 注入，恒 0）、11 事件丢弃（原键 5）、12 跨代重路由；
  13+ 为 sodama 自有（offload/探针/暂停计数），容量 24。
- 各键的 bump 点：conn_save 拆键；redirect insert 失败按满/其它拆分；无状态 TCP 直通
  （仅 WAN egress，LAN 侧改为 fail-closed）；parse 层带原因（`ParseSkip::FragTail` /
  `UnsupportedL4` → progs 计数）；`refresh_reverse_state` 对无主 UDP 计数 + 创建方向标记条目；
  `publish_redirect_track` 按错误码拆满/其它。
- **LAN ingress TCP fail-closed**（对照 dae `tproxy.c:3115-3133`）：TCP 且 conn_state 创建失败
  （表满）时，仅 `direct 且 mark=0` 放行，其余 `TC_ACT_SHOT`（防路由泄漏；WAN egress 维持
  无状态直通语义 + 计数键 6）。

### 8. 事件限速键域对齐 dae

- `event_rate_map` 容量 262（0..=261）；键域：0..255 per-outbound（BLOCKED_ALIVE）、
  256 blocked / 257 redirect_rebind / 258 overflow / 259 syn_rebind / 260 stateless_tcp /
  261 frag_tail。**per-CPU 实现保留**（aya-ebpf 无 64 位原子 CAS，ADR-0065 已记录）。

## 理由

- 十项都是「dae 有、sodama 缺」的机制面对齐；其中 2/3/5 是**行为级**缺口（出口全死时
  数据面直接阻断、背压失稳时的 fuse、规则换代后的重路由），4/9 是**状态面**缺口（重启
  保留、首包交接），1/6/7/8/10 是**观测/角色面**缺口。
- 全部落在既有架构内（map + 判定点 + 控制面投影），不引入新形态。

## 后果（正/负）

**正**

- §3 数据面 24 行判定全部「已完成」（余项为已记录的偏离）；程序数 22 → **24**（新增
  `lan_egress` L2/L3），map 22 → **26**。
- 出口全死时新连接在数据面被阻断（不再走完整 tproxy→relay→dial 失败链）+ per-outbound
  限速事件可观测。
- 规则 reload 后同 4 元组重连按新规则重路由（`syn_rebind_rerouted` 可数）；同代次误报
  SYN 被拒改（防欺骗 SYN 改写活跃流路由）。
- 进程重启后 conn_state（含在途流路由）经 pinning 迁移保留；handoff 表兜底首包路由读取。
- stats/事件键域与 dae 逐键对齐（0..12 + 262 限速键域），便于 dae 生态的观测经验直接复用。

**负 / 代价**

- **eBPF 栈预算是本批最难的约束**：`split_flow` 调用链 combined stack 一度超限
  （verifier 报 `528 > 512`，kernel 7.2.8 对子程序调用链累计 ≤512）。修复：`SodaEvent`(72B)、
  `SodaConnState`(24B)、`SodaRoutingHandoffEntry`(32B) 三个结构全部移出栈到 per-CPU scratch
  map；`conn_save` / `publish_routing_handoff` / `send_blocked_alive_event` /
  `refresh_reverse_state` 改 `#[inline(never)]` 独立子程序帧。**后续再加热路径代码前必须先看
  combined stack**。
- `lan_egress` 在每个 LAN 接口新增一个 egress 钩子（恒放行，开销 = 一次 parse）。
- fuse 的 engage 判定在本地回环夹具下不可自然触发（对端 retry 队列不积压）；真实触发
  依赖生产对端拥塞，lab 只验证生命周期/阈值/无残留（判定逻辑有单测）。
- pinning 迁移是一次性全表读（262144 条上限，启动期 ~50ms 量级）。

## 对 dae 的偏离清单

| # | 偏离 | 理由 | 证据分级 |
|---|---|---|---|
| 1 | 事件限速 per-CPU（dae 全局 ARRAY + CAS 严格 1 条/秒） | aya-ebpf 下 bpf 目标无 `target_has_atomic`（ADR-0065） | 实测（bpf 目标 `--print cfg`） |
| 2 | `bpf_conn_state_map_size` 仅启动生效（dae 在代次交接时重建 map） | sodama 无代次交接；重启 + pinning 迁移是等价路径 | 实测（容量变更需重启） |
| 3 | pinning 用「加载后 pin + 冷启动全表迁移」（dae 用 libbpf pinned map 复用） | aya 无 per-map pinned 复用；迁移语义等价且 generation 判定保证正确性 | 实测（`conn_state pin: 迁移 N 条`） |
| 4 | `datapath_generation` 启动随机非 0（dae 进程内递增从 1 起） | 避免与 pinned 旧条的代次碰撞（重启后必然异代） | 推断（设计论证） |
| 5 | handoff 条目 TTL 30s（dae 无显式 TTL，靠 reload 换代失效） | sodama 单进程无换代清扫，TTL 兜底陈旧条目 | 推断 |
| 6 | `SOCKMARK_FALLBACK`（键 10）恒 0 占位 | sodama 的 mark 校验走专用 socket 标记位，无 so_mark 注入回退路径 | 实测（代码路径不存在） |
| 7 | fuse 泵为「per-session 临时线程」（dae 用长期 relay goroutine + epoll 切换） | sodama 的 offload 会话常态 0 线程；fuse 是异常态，临时泵最简单 | 实测（fuse 期间才有线程） |
| 8 | LAN ingress TCP fail-closed 用「conn_save 失败」判定（dae 用 lookup miss） | 两者等价（save 失败 ⇔ 下包 lookup miss），sodama 少一次查表 | 推断（等价性论证） |

## 验证方式

- 单测：`cargo test --release` **310/310**（新增 `fuse_decision` 两阶段判定 2 项）。
- 内核级（QEMU 矩阵 7.2.8）：
  - `verify=PASS` 12/12（含 `rebind` —— stats 键重排后 `rebind_tool.py` 键号同步）；
  - `cap=PASS` **9/9**：既有 5 项（must/sub-file/hotplug/rules-cap/domain）+ 新增 4 项
    —— `test-gaps`（lan_egress 挂载 + parse 计数 + 同代 SYN 拒改 + 异代重路由 + handoff 表）、
    `test-alive`（组标死 → 数据面阻断 → 恢复）、`test-fuse`（阈值生效 + 无失败无残留）、
    `test-pinning`（pin + 重启迁移）。
- 开发期由 verifier 抓到的真实缺陷（全部已修）：
  1. **combined stack 528 > 512**（三结构 scratch 化 + 子程序化，见「后果」）；
  2. **fuse 两阶段 lift 死锁**：`lift 需 drained、drained 需 stop、stop 只在 lift 置位`——
     改为 DrainStart → Lift 状态机（纯函数单测锁定）；
  3. stats 键重排引发 lab 侧键号漂移（`rebind_tool.py` / `test_rebind` 同步到 dae 键域）。

## 未做 / 边界

- fuse 的真实触发（对端 retry 队列积压 > 64 MiB）在本地夹具不可构造，留生产观测；
- `bpf_conn_state_map_size` 的运行期变更（不重启）不做（偏离 2）；
- offload 会话本身在 QEMU 环境有既有首连抖动（devlog §19，信息项），`test-fuse` 的数据流
  部分对此做重试 + 可跳过，机制断言不受影响。
