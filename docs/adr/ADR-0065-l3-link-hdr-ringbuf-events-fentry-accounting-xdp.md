# ADR-0065：数据面对标批次——L3 链路头程序族 · ringbuf 事件通道 · `skb_send_sock` 记账（fentry/kprobe）· XDP 计量探针

- **状态**：已采纳（2026-10-16）
- **对应**：用户决策「开发 L2/桥接、kprobe/fentry、ringbuf、XDP 这些缺失的功能」
  （`docs/backlog.md` C1/C3/C4；`docs/parity-status.md` 域 1 的余项清单）
- **相关**：ADR-0024/0025（数据面 Rust 化 / 移除 C 数据面）、ADR-0033（pname cgroup 采集）、
  `docs/phase2-devlog.md` §15（AF-XDP 预研否决）、§19（本批次记录）、`docs/sodama-atlas.html`

## 背景

对照 dae 的数据面（`dae/control/kern/tproxy.c` 与 Go 侧绑定），`docs/parity-status.md` 域 1
列出四个缺口，本批逐一处理：

1. **L2/桥接程序族（C1）**：dae 的 TC 程序按链路头长度成对出现（`SEC("tc/lan_ingress_l2")` /
   `_l3`，共 12 个变体程序 + `dae0peer_ingress`/`dae0_ingress`），选择逻辑在控制面
   `control/control_plane_core_bind.go:61-77`（`linkHdrLen()`：netlink `EncapType` 为
   `none`/`ipip`/`ppp`/`tun` → 0，`ether` → 14，其它告警后按 14）。sodama 只有 7 个 TC 程序，
   `ebpf-rs/src/parse.rs` 硬编码 `ETH_HLEN=14`，因此对**无链路头接口**（tun/ppp/ipip/none）
   解析必然错位（把 IP 头当以太头读）。
2. **ringbuf 事件通道（C3）**：sodama 的调试手段只有 `bpf_printk`（M1 门控）。printk 无法结构化
   消费、无法限速、无法计数丢弃；dae 用 `event_ringbuf`（256KiB）+ `struct dae_event` 72B +
   每键 1s 限速 + `BPF_STATS_EVENT_DROP` 计数（`kern/tproxy.c:749-875`）。
3. **kprobe/fentry（C3 同批）**：offload（P4c/P8）只有 gating 计数（verdict 数/重定向数），
   没有「内核路径真实推送了多少字节」。dae 用 fentry/kprobe 挂在 `skb_send_sock` 上按
   （重定向前）四元组记账，服务于 per-key 背压 fuse（`kern/tproxy.c:4376-4393`、
   `kern/include/tcp_offload.h:tcp_offload_skb_key`、Go 侧 `control/tcp_offload_hook.go`）。
4. **XDP（C4）**：`docs/phase2-devlog.md` §15 与 `docs/research/af-xdp-feasibility.md` 已否决
   把数据面搬到 AF_XDP/XDP；backlog C4 的验收标准只是「调研报告（收益/兼容性）即可」，
   并推荐最小计量探针 + 结论。

## 决策

### 1. C1：L3 链路头变体（5 个新程序）

- 新增 `sodama_lan_ingress_l3`、`sodama_wan_egress_l3`、`sodama_wan_ingress_l3`、
  `sodama_wan_lan_ingress_l3`、`sodama_lan_wan_egress_l3`；既有 L2 版保持原名
  （`ebpf-rs/src/progs.rs`，角色体共用 `*_body(ctx, link_h_len)`）。
- 解析：`parse_ip_at(ctx, link_h_len)`（`ebpf-rs/src/parse.rs`）——L2 读以太类型字段判 v4/v6 并
  记 MAC；L3 读 `skb->protocol`（内核把该字段映射成与以太类型字段**同一字节形态**的 u16，
  可直接比较、也可原样写回补出的以太头，对照 dae `kern/tproxy.c:1103/2261/3042`），MAC 置 0。
- 挂载选择：loader `--link-hdr auto|l2|l3`（默认 `auto`），按
  `/sys/class/net/<if>/type` 判定（该值就是 netlink `IFLA_ARPHRD`，与 dae 的 `EncapType` 同源）：
  `1`→14B；`512`(PPP)/`768`(IPIP)/`769`(TUNNEL6)/`65534`(NONE,tun)→0B；其它按 14B + 告警（同 dae 默认分支）。
- 前向路径：L3 流的 `redirect_track` 条目 MAC 置 0（同 dae
  `fill_redirect_entry_from_forward_packet:2151-2164`）；重定向到控制面时若链路头为 0，
  先 `bpf_skb_change_head(+14)` 再 `bpf_skb_store_bytes` 写
  `h_proto = skb->protocol`、`h_source = 0`、`h_dest = dae0peer_mac`（同 dae
  `rewrite_packet_for_control_plane:2253-2279`，因为 `dae0peer` 是 veth、需要以太帧）。
- 回程路径：loader 把 L3 接口 ifindex 写进新 map `l3_ifindex_map`；`sodama0_ingress` 命中则
  **不写 MAC、不手工剥头**，直接 `bpf_redirect(ifindex, BPF_F_INGRESS)` 回原接口——
  L2 头的去除由 redirect 语义完成（实测：手工 `adjust_room(-14)` 会多剥 14B，见「偏离清单」#1）；
  并对 L3 流按「有回程 = 流仍活跃」续租
  （dae 在此形态下 MAC 比对恒失败、不续租，见「偏离清单」#2）。

### 2. C3：ringbuf 事件通道

- 数据面新增 `event_ringbuf`（`RingBuf<SodaEvent, 256KiB>`）、`SodaEvent`（72B，
  `#[repr(C)]`，字段布局对照 `struct dae_event`）、事件类型常量
  （0 blocked / 1 UDP 溢出 / 2 TCP 溢出 / 4 rebind 拒斥 / 8 redirect 更新失败；
  3/5/6/7/9 保留未实现，编号不占用）、`event_rate_map`（键 256/257/258 = blocked/rebind/overflow，
  与 dae `EVENT_RATE.*_key` 同址；窗口 1s）+ `SODAMA_STAT_EVENT_DROPS`（ringbuf 满丢弃计数）。
  发送入口 `ebpf-rs/src/event.rs::{send_event, send_event_limited}`。
- 原 printk 落点全部改为事件：blocked（`flow.rs` split_flow）、rebind 拒斥（`publish_redirect_track`）、
  redirect 更新失败、conn_state 写失败（新增 `SODAMA_STAT_CONN_OVERFLOW` + TCP/UDP 溢出事件）。
  `--ebpf-debug` 门控的少量调试打印保留（M1）。
- 用户态：`Ebpf::load` 后 `take_map("event_ringbuf")` → 常驻线程 `ebpf-events`
  （`poll` + 排空 `RingBuf::next`，长度不符按 unknown 计数不 panic），逐事件计数 +
  **1 条/秒/类型**日志限速（多余计入 suppressed），status 增 `events`
  （`consumed`/`suppressed`/`by_type`/`dropped_kernel`），metrics 增
  `sodama_events_total`/`sodama_events_suppressed`/`sodama_event_drops`。

### 3. `skb_send_sock` 记账（fentry 优先，kprobe 回退）

- 数据面新增 `ebpf-rs/src/trace.rs`：`#[fentry(function = "skb_send_sock")]`
  `skb_send_sock_account` 与 `#[kprobe(function = "skb_send_sock")]` 影子
  `skb_send_sock_account_kprobe`，共用 `account()` 主体：
  按 `trace_param_map` 给出的 `sk_buff` 字段偏移（`network_header`/`transport_header`/`tail`/`head`）
  用 `bpf_probe_read_kernel` 读（与 dae `tcp_offload_skb_key` 同顺序、同合法性判定），
  构造四元组键，**先查 `offload_guard` 过滤**（只记本进程注册的 offload 键），
  再累加 `len` 到 `offload_sent`（`PerCpuHashMap<SodaTuple, u64, 8192>`）与全局
  `SODAMA_STAT_OFFLOAD_SENT_BYTES`；表满计 `SODAMA_STAT_ACCOUNT_DROPS`。
- **CO-RE 替代**：aya-ebpf 无 `bpf_core_read`/`BpfCoreAccessors`（且 bpf 目标不可用 `bpf_loop`/kfunc，
  见 `route.rs` 注释）。新增 loader 模块 `loader/src/btfoff.rs`：纯 std 最小 BTF 解析器
  （kind 跳表 + 匿名 struct/union 递归成员查找），启动时从 `/sys/kernel/btf/vmlinux` 解出
  真实偏移写入 `trace_param_map`；解析失败则跳过探针并记一行日志（计量降级，不影响转发）。
- 挂载：`attach_offload_accounting()` 先 `Btf::from_sys_fs()` + `FEntry::load("skb_send_sock", &btf)`
  + `attach()`，任一失败回退 `KProbe::load()` + `attach("skb_send_sock", 0)`（对照 dae
  `control/tcp_offload_hook.go` 的选用：无 `CONFIG_DYNAMIC_FTRACE` 或目标被直接调用/trampoline
  占用时 fentry 会 EBUSY）。仅在 `--offload` 下挂载。
- 用户态回收：`take_map("offload_sent")` → `OFFLOAD_SENT`；键摘除点
  （`offload_watch_cleanup` 与 `handle_relay_conn` 尾部）调用 `offload_sent_reclaim(key)`
  （per-CPU 求和 → 累计 `RELAY_STATS.offload_sent_bytes` → `remove`），status 增
  `offload_sent.{reclaimed_bytes, kernel_bytes, account_drops}`。

### 4. C4：XDP 计量探针（零干预）

- 新增 `ebpf-rs/src/xdp.rs` 的 `#[xdp] sodama_xdp_observe`：**恒返回 `XDP_PASS`**，
  只做计量（包数/字节/IPv4/IPv6/其它，per-CPU `xdp_stats_map`）；不做 redirect/drop/改写。
- loader：`--xdp <iface>`（可重复，默认不挂），`Xdp::attach(iface, XdpMode::Default)`，
  失败仅告警；status 增 `xdp`（未挂载为 `null`，区分「0 包」与「没有探针」），metrics 增
  `sodama_xdp_packets`/`sodama_xdp_bytes`。

## 理由

- **语义对齐优先**：程序名、事件编号、限速键、map 名尽量与 dae 同名同位，便于逐项对拍与回溯。
- **观测不改变转发**：C3（事件）与 C4（XDP）都设计成「可计数、可限速、可关闭、失败即降级」，
  避免新增路径影响转发正确性；C4 的探针恒 `XDP_PASS`，最坏情况只是计数不准。
- **不硬编码内核结构偏移**：生产 6.12 与开发机 6.18 的 `struct sk_buff` 偏移不同
  （本机 pahole 实测 182/184/188/200），硬编码必然随内核/编译选项漂移；用户态 BTF 解析
  是 aya 生态下 CO-RE 的最小可行等价物。
- **记账先过滤再累加**：sodama 的 relay 侧可能同时有 kTLS 等其它 `skb_send_sock` 调用方，
  无条件建键会把无关流量算进来（dae 的 `tcp_offload_sent` 无回收路径，会被无关流量撑大）；
  `offload_guard` 已是现成的注册键镜像，复用它做过滤。

## 后果

正面：域 1 的 L3 缺口补齐（tun/ppp/WireGuard 等形态可分流）；热路径调试从 printk 迁移到
可结构化消费、可限速、可计数的事件通道；offload 有了「内核路径真实推送字节」的计量
（可验证 offload 是否真的在推数据）；XDP 有了零风险计量底座（保留 C4 的调研结论与实测入口）。

负面 / 代价：

- 数据面对象 496K → 772K（3 个新 program section + 5 个新程序 + 探针诊断计数；`llvm-readelf` 实测）。
- 事件限速的「本秒抑制 N 条」实际统计的是「距上次输出以来」的抑制数（静默期拉长时会覆盖整个
  间隔），非严格 1s 滚动窗口。
- `offload_sent` 的「读 → 删」之间数据面仍可能继续累加，尾账随删除丢弃（接受的小误差）。
- L3 回程改为「只 redirect、不手工剥头」（见「偏离清单」#1）：语义依赖内核 redirect 到
  无链路头设备时自行去 L2 头；已在 QEMU（7.2.8）端到端实测，但生产 6.12 + 真 tun/ppp
  仍待回验。

## 偏离清单（与 dae 的显式差异）

| # | 项 | dae | sodama | 理由 |
|---|---|---|---|---|
| 1 | L3 回程报文形态 | `tproxy_dae0_ingress` 一律按以太处理：写 MAC + `bpf_redirect`（原接口是 tun/ppp 时包上会多 14B） | 按 `l3_ifindex_map` 判定，L3 目标**跳过 MAC 改写、直接 redirect**（不手工剥头） | 修正 dae 在无链路头接口上的形态缺陷（详 `sodama/NOTES.md`）；手工 `adjust_room(-14)` 实测会多剥 14B——redirect 到 L3 设备时内核自己会去 L2 头（十六进制取证：外层 `total_length=66` 应为 80，载荷从内层 IP 头第 14 字节起） |
| 2 | L3 回程续租 | MAC 比对（`reply_publisher_matches`）对 L3 条目恒失败 → 不续租 → 反向活跃、正向静默的流会被 janitor 过期 | L3 流按「有回程 = 流仍活跃」续租 | 同上；L3 无 L2 发布者可比，权衡后选可用性 |
| 3 | 事件限速严格性 | 全局 ARRAY + `__sync_val_compare_and_swap` 严格 1 条/秒/键 | per-CPU ARRAY，上界 = CPU 数/秒/键 | bpf 目标无 64 位原子 RMW：`rustc +nightly --print cfg --target bpfel-unknown-none` 只给 `target_has_atomic_load_store`（实测），Rust 侧无 `AtomicU64::compare_exchange` |
| 4 | 记账过滤 | 无条件建键/累加（任何 `skb_send_sock` 调用方都会进表） | 先查 `offload_guard`（只记 offload 注册键） | 避免无关流量（kTLS 等）污染与撑表 |
| 5 | 记账消费 | per-key 读数驱动背压 fuse（超水位暂停重定向） | 只在键摘除时汇总（无 fuse） | 本批次只做计量；fuse 属转发控制，待后续单独批次 |
| 6 | `struct sk_buff` 字段读取 | clang CO-RE（`BPF_CORE_READ_INTO`） | 用户态 BTF 解析 + `bpf_probe_read_kernel` | aya-ebpf 无 CO-RE field access（`BPF_CORE_READ_INTO` 在 dae 源码里也是自写宏） |
| 7 | 事件限速键域 | 0..255 outbound + 256..261 保留 | 0..255 预留 + 256/257/258（`BLOCKED_ALIVE`(3)/`SYN_REBIND`(5) 等未实现的事件类型与其键一并保留） | 只实现有消费者的子集，编号不占用 |

## 验证方式

**已实测（内核级，QEMU 内核矩阵 7.2.8-arch1-2，2026-10-16）**：

- 回归门禁 `lab/matrix.sh vm` 的 `lab.sh up && verify`：**12 项全绿**（原 9 项 + 新增 `l3-attach`/`l3`/`xdp`），
  证明改动后的数据面（含新 map/新程序/parse 与 flow 重构）在新内核上**通过 verifier 且无回归**；
- `_l3` 变体选择与挂载（`landae3` arphrd=768 → `sodama_lan_ingress_l3`，见 `bpftool net show`）；
- **L3 端到端已过（本次收口）**：`test-l3` 经 ipip 隧道——小连接拿到
  `orig_dst=1.1.1.1:8080`（证明分流进 tproxy）+ 512KB 回显逐字节一致（双向经隧道，
  `stream-ok bytes=524288`）；配套修复三件事：①回程只 redirect 不剥头（同上「偏离清单」#1）；
  ②隧道 MTU 1466 + 专用 underlay veth + 两端关 offload（新增 `lab/net_offload.py`，免 ethtool）；
  ③loader 回显夹具去除 8 次读上限（>32KB 会被 RST，曾误诊为 MTU 问题）。`test_l3` 已入
  `verify` 门禁（SKIP 条件：无 ipip/无法建隧道）；
- fentry `skb_send_sock` **挂载成功**（偏移由运行内核 BTF 解出：7.2.8 上亦为
  `nh=184 th=182 tail=188 head=200`）；探针 `probe_calls` 随流量增长；
- 记账链路端到端：`kernel_bytes=1050069` 且 `reclaimed_bytes=1050069`（单轮），6 轮累计
  `kernel_bytes=5289555`、`probe_parse_fail=0`；
- XDP 探针挂载并计数（`packets/bytes/ipv4/ipv6/other`，`test-xdp` 断言 `packets>0 && ipv4>0`）；
- L3 补头/剥头 helper 在内核里逐次成功（`change_head=0 proto=0x8`、`adjust_room=0`）——
  M1 `--ebpf-debug` 采样取证；**并借此抓到并修掉一个真实缺陷**：探针误把 `head+0`
  当版本字节读（采到 `v=0x0/0x52` = 以太目的 MAC 首字节）导致 100% 解析失败，
  改为 dae 同口径的 `head+nh` 后 `parse_fail=0`。

**未通过 / 仍属推断**（验收放到生产）：

- offload 用例在本 QEMU 环境有**既有抖动且随宿主状态大幅波动**：2026-10-16 重启后，
  四组对照（全配 / `NO_L3=1` / `SKIP_NET_OFFLOAD=1` / 基线 5092723 重编译）**全部 9/9 失败**
  ⇒ 与本批无关，环境因素；签名指向 offload 注册交接竞态（问候超时 / 首连降级），
  已登记入 devlog §19 待下批调查；
- verifier 在 6.12（生产内核）上的行为、kprobe 回退路径（VM 上 fentry 直接成功未触发回退）、
  L3 在生产 tun/ppp 接口上的实际表现（lab ipip 已端到端过关）。

**已实测（本机构建/单测，2026-10-16）**：

- 数据面构建：`cd sodama/ebpf-rs && cargo +nightly build --release` 通过；
  `llvm-readelf -S` 确认 `fentry/skb_send_sock`、`kprobe/skb_send_sock`、`xdp` 三个新 section；
  `llvm-nm` 确认 5 个 `*_l3` 程序符号；`bpftool btf dump … format raw` 确认 map 容量
  （`event_ringbuf`=262144、`event_rate_map`=259、`l3_ifindex_map`=64、`offload_sent`=8192、
  `xdp_stats_map`=8、`sodama_stats_map`=16）与结构体尺寸（`SodaEvent`=72B、`SodaTraceParam`=16B）。
- 用户态：`cargo test` **302 passed**（含 `btfoff` 14 项：合成 BTF 全 kind 尾随长度、匿名
  struct/union 递归、截断/坏 magic/字符串越界返回 Err；真机解析结果与 `pahole -C sk_buff
  /sys/kernel/btf/vmlinux` 完全一致：`network_header=184, transport_header=182, tail=188,
  head=200`）；`cargo clippy -p sodama` 无新增 error（既有 3 条历史遗留不变）；
  musl 交叉构建 `lab/build-openwrt.sh --arch x86_64` 通过（产物 `sodama 7.7M · sodama-ebpf 772K`）；
  `--help` 与 `--link-hdr bogus` 非法值路径行为正确。

**未实测（本机无 CAP_BPF、无免密 sudo）**——以下为**推断**，验收放到 lab/生产：

1. 生产内核（6.12）上新增程序的 verifier 接受度与 fentry/kprobe 挂载结果（矩阵在 7.2.8 上已验证，
   见上一节；6.12 待生产回验）；
2. kprobe 回退路径（需 fentry 因 EBUSY/无 DYNAMIC_FTRACE 失败的场景）；
3. L3 在真实 tun/ppp 接口上的端到端（lab 侧 ipip 隧道已过关，见上文）。

**验收命令（staging/生产，需 root）**：
`status` 看 `events.{consumed,suppressed,by_type,dropped_kernel}`、
`offload_sent.{reclaimed_bytes,kernel_bytes,account_drops}`、`xdp`；
日志 grep `offload 记账:` 与 `event:`；`--xdp` 挂载后确认转发不受影响（探针恒 `XDP_PASS`）。

## 余项（本批未做，登记在 `docs/backlog.md`）

- `lan_egress` 角色（dae 的 `tproxy_lan_egress_l2/_l3`，容器/独立 netns 出口用法）——sodama 从未实现，
  backlog C1 未列；若要补，需连同 `dual-role` 的第 4 种组合一起设计。
- 记账的 per-key 背压 fuse（dae 用它把暂停键上的流量交回用户态）。
- `DAE_EVENT_*` 未实现类型：3（blocked_alive）、5（syn rebind rejected）、6/7/9。
