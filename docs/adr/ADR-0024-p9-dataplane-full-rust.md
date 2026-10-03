# ADR-0024：P9 数据面全量 Rust 化（8 程序 / 14 map 全量移植，默认数据面切换）

- **状态**：已采纳（2026-10-04）
- **对应**：ADR-0002「先 C 后迁」的完成；取代 ADR-0023 的**迁移路线部分**（垂直切片/双对象共存），
  0023 记录的 offload guard 与验证口径仍然有效
- **相关**：ADR-0002、ADR-0010（规则对拍）、ADR-0015/0021/0022（offload 与运维面）、NOTES §11.13/§11.14

## 背景

ADR-0023 打通了工具链并完成 offload 垂直切片（双对象共存）。P9 把剩余 7 个 TC classifier
与规则 VM 全部移植到 aya-ebpf，产出**单一完整 Rust 对象**（8 程序、14 map，与 C 对象同名同型），
并把 lab 默认数据面切换为 Rust（`USE_EBPF_C=1` 可回退）。

## 决策

1. **单对象全量**：`ebpf-rs/` 现在包含全部数据面。程序与 map 的名字/类型/容量/section 与 C 逐一对齐，
   loader 无分支——`--ebpf <rust.o>` 即可（lab：默认指向 Rust 对象，`USE_EBPF_C=1` 指回 C）。
2. **BTF maps**：`#[btf_map]` + `btf_maps::{Array, ArrayOfMaps, HashMap, LpmTrie, PerCpuArray, SockHash, SockMap}`；
   `lpm_array_map` 用 `ArrayOfMaps<LpmTrie<[u8;16], u32, 1024>, 128>`（内层模板进 BTF）；
   `domain_routing_map` 用 `BPF_F_NO_PREALLOC`。`bpf-linker --btf` 需要 debuginfo：crate profile
   设 `debug = 2`，否则对象无 `.BTF`，aya 报 `no BTF parsed for object`。
3. **规则 VM 用有界循环，不用 `bpf_loop`**：aya-obj 对函数指针的 `R_BPF_64_64` relocation 未产出内核
   要求的 `BPF_PSEUDO_FUNC` 语义（实测 verifier：`callback function not static`）。规则上限 64 已先验证明，
   内核 ≥5.3 对特权程序支持 bounded loop，语义与 C 等价（下一批可在 aya-obj 支持后换回 bpf_loop）。
4. **其余移植要点**：
   - 报文解析全走 `ctx.load::<T>()`（bpf_skb_load_bytes），不依赖直接包访问；
   - `skb->mark` / `skb->ifindex` 通过 `TcContext.skb.skb` 原始指针读；
   - MAC 改写用 `ctx.store::<[u8;6]>()`；`bpf_skb_change_type` / `bpf_redirect(flags=BPF_F_INGRESS)` 同 C；
   - `dae0peer_ingress` 的 `listen_socket_map` → `bpf_sk_assign`：aya-ebpf 的 SockMap 只暴露
     SK_LOOKUP 场景方法，这里用 `bpf_map_lookup_elem(&listen_socket_map, &key)` + `bpf_sk_assign/bpf_sk_release`；
   - offload 的 `offload_guard` 预检镜像保留（aya-ebpf 仍未暴露 SockHash lookup）。
5. **默认切换**：lab 的 `up()`/`dual_up()` 在 Rust 对象存在时默认加载它；C 对象保留为回退与对照。

## 理由

- 单一对象消除双对象/计数合并的复杂度，失败面更小；loader 零改动是「布局逐字节对齐」的直接回报；
- 先证伪最大未知（BTF map-in-map、verifier、bpf_loop relocation），再全量铺开；唯一未按原路走通的是
  `bpf_loop`，用有界循环绕开且语义等价；
- 回归网是现成的（verify/DNS/协议梯/运维/soak），可以按 C 的同一口径验收。

## 后果

- 正面：**eBPF 程序本体不再是 C**——数据面 100% Rust（aya-ebpf + BTF maps）；
  8 程序/14 map 全量移植；默认数据面已是 Rust 且全量回归通过；C 对象仅作回退/对照。
- 负面/代价：规则 VM 目前是有界循环（最大 64 条规则下与 bpf_loop 等价；规则上限提升时要重估）；
  两份实现（Rust + C 回退）短期并存需同步（以 lab 回归约束）；对象因 debuginfo 体积增大（约 274KB）。
- 风险：`bpf_loop` 的 relocation 缺口在上游 aya-obj 修复前不能用；TCP flags 等位段语义的移植
  错误会静默降级（本次实测抓到 SYN 位错位，已由 verify 回归钉住）。

## 验证方式（实测）

- **整对象**：`rs-up`（标准拓扑）与 `rs-dual-up`（单臂）加载/attach 全过（含 BTF map-in-map 创建）。
- **全量回归（Rust 数据面）**：标准 verify 9/9；单臂 verify 8/9（`rebind` 首轮时序抖动，单跑
  9/9，与 C 数据面同类 flake）；DNS 六专项；转发面六专项（含 offload 生命周期）；
  G1/G2（ss/ss-udp/trojan/vless/vless-udp/vmess/vmess-udp）、G3（tuic/tuic-udp/hy2/hy2-udp/
  hy2-obfs/hy2-brutal/hy2-hop）；`test-ops`/`test-config-reload`；`cargo test` 73/73；
  Rust 数据面 soak 30s（450 轮 + reload/suspend，RSS +372kB、fd +0、回收归零）。
- **性能（单次取数，量级对比）**：direct 30.4Gbps/10µs（C 31.1/10µs）；relay 20.4Gbps/18µs
  （C 24.7/17µs）；offload 11.9Gbps/21µs（C）vs offload-rs 10.8Gbps/19µs（Rust 全对象）；
  ping-pong 微秒级对齐。
- **默认切换**：默认会话加载 `mini-dae-ebpf`（日志 `loading .../mini-dae-ebpf`）且 `test-proxy` 通过；
  `USE_EBPF_C=1` 回退加载 `mini_dae.o` 同样通过。

## 修订条件

若 aya-obj 支持 `BPF_PSEUDO_FUNC` 且规则规模需要 `bpf_loop`，另写 ADR 换回；
若移除 C 对象（删 `ebpf/mini_dae.c` 与 `USE_EBPF_C` 回退），另写 ADR 记录；
规则上限提升（>64）时必须重评有界循环的 verifier 成本。
