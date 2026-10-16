# ADR-0066：能力缺口批次 #1–#4——`must_<组名>` 糖 · 订阅 `-file` scheme · 接口懒绑定/热插拔 · `match_set` 容量 1024

- **状态**：已采纳（2026-10-16）
- **对应**：用户决策「先做到 1-4」——`docs/capability-gap-review.md`
  「我最有把握的 top 10 缺口」的 #1–#4 四项（含 §2/§3/§4 各表的判定更新）
- **相关**：ADR-0012（域位图）、ADR-0043（规则按组名选组）、ADR-0061/0062（订阅顺序与配置源）、
  ADR-0065（数据面对标批次）、`docs/phase2-devlog.md` §20（本批次记录）、
  `docs/sodama-atlas.html`

## 背景

`docs/capability-gap-review.md`（2026-10-16 清点，110 行判定：26 未做 / 39 部分 / 45 已完成）按
「日常代理网关影响」排出 top 10 缺口，本批处理前 4 项：

1. **`must_<组名>` 前缀糖未实现且静默映射为 proxy**（§2）：dae 语义 `must_groupname` ≡
   `groupname(must)`（`dae/config/patch.go:71-95` `patchMustOutbound`，含 fallback 的
   `must_x` 展开；`dae/docs/zh/configuration/routing.md:14` 明示等价）。sodama 只特判
   `must_direct`，其余 `must_<组名>` 落入兜底分支**静默变成 proxy**——写 `must_proxy` 的流量
   被当成 `proxy` 处理（DNS 也会被劫持，正是 `must` 想避免的），且没有配置错误提示。
2. **订阅 `http-file://` / `https-file://` scheme 缺失**（§2）：dae 用该 scheme 表达「优先拉取、
   失败回退磁盘缓存」（`dae/common/subscription/subscription.go:171-179`、`:213-241` 先解析成功
   再落盘 `persist.d/<tag>.sub`）。sodama 只认 `file://`/裸路径/`http(s)://`，且订阅节点缓存
   **纯内存**（`subscribe.rs:46-95`、`main.rs` 的内存缓存）——路由器重启 + 订阅源不可达 =
   零节点启动（有生产事故先例）。
3. **接口懒绑定/热插拔缺失**（§4）：dae 在接口出现时自动补挂（`component/interface_manager.go:38-50`
   netlink 订阅 + `path.Match`；`cmd/run_config.go:129-157` `wan_interface: auto` →
   `GetDefaultIfnames`）。sodama 只在启动时按**精确名字**挂一次；`lan_interface`/`wan_interface`
   配置键解析了不生效；接口变动后流量**静默不被接管**。
4. **`routing_map` 上限 64 vs dae 1024**（§3）：`SODAMA_MAX_MATCH_SET_LEN = 64` 决定
   「大规则集能不能上线」；超限编译期报错拒启（不静默，但配置改不动）。P9 迁移期选择有界循环
   而非 `bpf_loop`（ADR-0024），因为当时 aya-obj 对回调函数指针的 relocation 不产生
   `BPF_PSEUDO_FUNC`（verifier 报 `callback function not static`）。

## 决策

### 1. `must_<组名>` 糖 + `must` 投递侧语义

- **配置面（`loader/src/config.rs`）**：`map_outbound`（`:1710`）实现 `must_<名称>` →
  `<名称>(must)`（`must_rules` 保留字不展开；未定义组仍保持 K3 兼容回退 proxy，但
  `(must)` 语义不丢——dae 同形为 fallback 的 `must_x` 展开）。
  新增 `append_must`（`:1747`）、`apply_outbound_params`（`:1765`）、`split_outbound_params`
  （`:1797`）：**同时修掉另一处静默丢语义**——`--config` 路径此前丢弃规则 outbound 的
  `(must)`/`(mark: 0x…)` 参数（`extract_routing` 只取 `.name`）；不认识的参数整条进 deferred，
  不静默改语义。
- **数据面（`ebpf-rs/src/flow.rs:326`）**：`conn_save` 条件从「非 UDP-53」改为
  「非 UDP-53 **或** must」——普通 DNS 保持不存（热路径开销不变），`must` 的 UDP-53 流要存
  conn_state，交付侧据此区分「劫持到本地 DNS」与「按普通代理流转发」。
- **交付侧（`loader/src/main.rs`）**：新增 `lookup_conn_state`（`:3097`，返回整条
  `SodaConnState` 含 `must`；原 `lookup_conn_outbound` 改为其薄封装）。
  - TCP-53 DNS 劫持分支（`serve`/`handle_tproxy_conn`，`:2514-2529`）加 `must == 0` 条件；
  - UDP 监听器（`dns_loop`，`:7279-7285`）：`orig_dst.port() == 53` 且 `must != 0` → 走 UDP NAT
    会话表（组选择复用既有 `resolve_group_dialer` 的 conn_state 回读）。

### 2. 订阅 `http(s)-file://` scheme（磁盘回退口径不变）

- `subscribe.rs` 新增 `normalize_url`（`:33`）：`https-file://` → `https://`、
  `http-file://` → `http://`；接入 `fetch`/`fetch_lenient`/`fetch_once`、URL 文件间接路径
  （`url_file_target` 返回值改 `Option<String>`）与 `main.rs::resolve_sub_url`（缓存键一致性）。
- **磁盘落盘/回退机制本就存在**（`subscribe.rs:639-680` 的 `disk_cache_path`/`disk_store`/
  `disk_load`，`sub-cache/<tag>.bin`；调用点在 `main.rs`）：dae 的 `persist.d/<tag>.sub`
  语义等价物，本批只补 scheme 识别。
  口径与 dae 一致：**先解析成功再落盘**，拉取失败回退磁盘缓存（`sub_cache_ttl: 0` 只关内存
  缓存，不影响磁盘回退）。

### 3. 接口懒绑定/热插拔（轮询实现，偏离 dae 的 netlink）

- 新模块 `loader/src/ifwatch.rs`：
  - `Role`/`Spec`/`pattern_matches`（`:46`，`path.Match` 风格 glob，含 `[...]`/`[!...]`；
    对照 dae 同款匹配语义）；
  - `list_interfaces`（`:138`，读 `/sys/class/net`）、`parse_default_v4/v6`（`:151/:163`）、
    `default_route_ifaces`（`:181`）、`expand_auto`（`:203`，`auto` → 默认路由接口）；
  - `IfWatch`（`:228`）：`poll`（`:253`，比对新增/移除）、`initial`（`:279`）、`roles_for`。
- `main.rs`：`Args.lan_given/wan_given`（`:1386`，解析期记录 CLI 是否显式给出）；
  `split_iface_list`（`:2192`）；`attach_role`（`:2140`，启动与 watcher 共用挂载路径；
  `register_l3_ifindex` 改返回 `Option<u32>`，新增 `unregister_l3_ifindex`（`:2128`））。
  启动挂载块改为 specs → `IfWatch::new` → `initial` → `attach_role`（`:6039-6044`）；
  主循环每 1s `ifwatch.poll()` 补挂/清理（`:6352-6374`，含 `HOOKS` 与 `l3_mounts` 记账）；
  config 回填 `lan_interface`/`wan_interface`（CLI 优先）。
- **偏离**：dae 用 netlink 订阅（即时事件），sodama 用 1s 轮询 `/sys/class/net` + 默认路由解析。
  理由：避免引入 netlink 库/自实现协议依赖，1s 粒度对「网卡插拔/接口改名的接管时延」足够；
  代价是接管有最多 ~1s 延迟（记录为偏离 #1）。

### 4. `match_set` 容量 64 → 1024（`bpf_loop` 路线，含 domain 位下标编码修正）

- 常量与 map：`common.rs:14` `SODAMA_MAX_MATCH_SET_LEN = 1024`（与 `dae/Makefile:14`
  `MAX_MATCH_SET_LEN ?= 1024` 同口径）；`SodaDomainRouting.bitmap` 改为
  `[u32; MAX/32]`（`common.rs:311`）；`maps.rs:24` `routing_map` = `Array<SodaMatchSet, 2*MAX>`；
  `maps.rs:18` `lpm_array_map` = `ArrayOfMaps<_, 2*MAX+8>`；`rules.rs:40` 同步 1024。
- **数据面扫描改用内核 `bpf_loop`**（`ebpf-rs/src/route.rs:253-260`）：aya-obj 0.3.0 已支持
  `BPF_PSEUDO_FUNC` 重定位（`aya-obj` `relocation.rs` 对非调用文本引用设置），ADR-0024 时代的
  缺口已修。回调 `route_bpf_loop_cb`（`route.rs:275`，`extern "C" fn(u32, *mut c_void) -> i64`，
  返回 0 继续 / 1 停止），`ctx` 传 **NULL**（内核只允许栈指针或 NULL），回调内从
  `route_ctx_scratch_map` 取回上下文。
- **domain 位下标改为 loader 预计算**（`rules.rs:1035-1039` 编译期、
  `:1136-1137` 跨规则拼接）：`bitmap` 的 `word_idx`/`bit` 写进 `match_set.value[0..2]`；
  数据面 `route_match_domain_set`（`route.rs:48`）从 `value` 读并单检查
  `word_idx >= MAX/32`。**不能**从 `bpf_loop` 回调参数推导下标：回调的 u32 参数会被 LLVM
  二次物化，verifier 无法把上界传下去（`bitmap[(index>>5)]` 报越界可能，实测）。

## 理由

- #1/#2/#3 是「用户可感知或静默出错」类缺口（top 4 的排序理由）：语义错、启不来、不接管。
  三项都是**对齐 dae 既有语义**的最小改动，不加新形状。
- #4 的分路线经实测选定：有界循环 verifier 成本随上界线性增长（见「后果」实测数据），
  `bpf_loop` 成本与迭代数无关——是对齐 dae 1024 的唯一现实路径；顺带修掉 domain 位图在
  `bpf_loop` 形态下无法表达下标的问题（改为数据面不消费下标）。
- `must` 的投递侧语义必须成套落地：只做配置面糖会把「must 的 DNS 不劫持」语义挂空
  （数据面不存 conn_state → 交付侧无法区分）——故同批改 `conn_save` 条件与两个交付分支。

## 后果（正/负）

**正**

- `must_<组名>` 与 dae 等价（含 fallback 展开），`--config` 路径的参数不再静默丢失；
  `must` 语义端到端可验证（`l4proto(udp) && dport(53) -> must_proxy` 的 DNS 流按代理流转发）。
- 订阅可用 dae 风格 `http-file://`/`https-file://`；重启 + 源不可达时磁盘缓存兜底
  （既有机制，本批接入 scheme）。
- 接口 pattern + `wan_interface: auto` 生效；接口出现/消失 1s 内自动补挂/清理
  （含 L3 接口的 `l3_ifindex_map` 记账）。
- 规则容量对齐 dae 1024：`test-rules-cap` 实测 71 个 match_set 通过 verifier，
  上限满配 1024 可用（大规则集可上线）。

**负 / 代价**

- 接口接管有最多 ~1s 延迟（轮询）；netlink 订阅未做（偏离 #1）。
- domain 位图的 word/bit 编码进入 `match_set.value` 的载荷契约（loader 与数据面必须同批
  升级；跨规则拼接必须重定位——本批已修，单测抓到过一处遗漏）。
- `bpf_loop` 需要内核 ≥ 5.17（矩阵门禁原口径），<5.17 时路由扫描不可用（加载即失败）。

## 验证方式

- 单测：`cargo test --release` **308/308**（新增 `must_` 糖、outbound 参数保留、
  `normalize_url`、`ifwatch` 3 项、domain 位下标编码 3 处断言；其中
  「跨规则拼接的 domain 位下标重定位」单测在开发中抓到真实缺陷）。
- 内核级（QEMU 矩阵 `lab/matrix.sh vm`，内核 7.2.8-arch1-2，`asserts` 全实测）：
  - `verify=PASS` 12/12（原回归门禁不回退）；
  - `cap=PASS` 5/5：`test-must`（must 的 UDP-53 不劫持 + 代理交付）、
    `test-sub-file`（`http-file://` 拉取成功 + 落盘 + 源掉线 SIGHUP 回退磁盘缓存后仍可拨号）、
    `test-hotplug`（启动 `hplug*` 无匹配 → 懒绑定提示；创建接口后自动补挂 → 分流；
    删除 → 清理；重加 → 再挂）、`test-rules-cap`（71 match_set + 高位规则命中）、
    `test-domain`（DNS 接管 → 域位图 → domain 规则分流的端到端回证，本批 domain 编码的回归）。
- 离线：`--compile-dump` 对 `rules.dns.dae` 的输出核对（`direct(must)` 的 `must=1`、
  DomainSet 的 `outbound=0xff` 中间条件槽）。

## 对 dae 的偏离清单

| # | 偏离 | 理由 | 证据分级 |
|---|---|---|---|
| 1 | 接口热插拔用 1s 轮询 `/sys/class/net`，非 netlink 订阅 | 免 netlink 依赖；接管时延 1s 量级可接受 | 实测（`test-hotplug` 日志时序） |
| 2 | `wan_interface: auto` 展开为「默认路由接口」而非 dae 的 `GetDefaultIfnames` 全量语义 | 取与 dae 同源的默认路由判定（v4/v6 `default` 行） | 实测（`ifwatch.rs:181`；两版本一致的部分） |
| 3 | domain 位下标编码进 `match_set.value[0..2]`（dae 由 C 侧从循环下标推导） | `bpf_loop` 回调参数不可作数组下标（verifier 实测） | 实测 |
| 4 | `must` 的 UDP-53 流存 conn_state（dae 在 C 侧用独立状态位区分） | 控制面需要 conn_state 回读才能选组 | 实测（`test-must`） |

## 未做 / 边界

- `must_rules` 关键字本身维持保留（数据面 `SODAMA_OUTBOUND_MUST_RULES` 状态位路径不变）；
- 订阅 SIP008 格式、链式代理 `chains` 不在本批（仍列 top 10 之后）；
- 接口移除时的**已建连接**不做主动清理（与启动挂载同口径，靠无状态放行兜底）。
