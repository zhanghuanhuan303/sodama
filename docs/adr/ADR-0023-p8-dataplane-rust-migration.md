# ADR-0023：P8 数据面 Rust 迁移（起步）——offload 垂直切片、双对象共存、guard 镜像

- **状态**：已采纳（2026-10-04）
- **对应**：ADR-0002「先 C 后迁」的启动；路线图新增 P8
- **相关**：ADR-0015（offload 设计）、ADR-0022（P7 offload 生命周期修复）、NOTES §11.13 §12

## 背景

- 全项目唯一未 Rust 化的核心是 eBPF 数据面：`ebpf/mini_dae.c`（1142 行，8 个程序、
  14 张 map）。原阻塞不在代码而在环境：官方 `static.rust-lang.org` / `static.crates.io`
  被网络策略 TLS 拦截，装不了 nightly/`rust-src`，也拉不到 `aya-ebpf`。
- 环境已解决（见 NOTES §11.13）：nightly + rust-src 走 Tuna 镜像；crates 走 USTC 完整镜像
  （`~/.cargo/config.toml` 源替换，index 与 dl 都在 USTC）；`bpf-linker 0.11.1` 本机已有。
- 迁移策略：不做一次性全量重写。选 **offload verdict** 做垂直切片——它最小、自包含
  （sockhash + sk_skb），且 P7 刚为它建立了回归（`test-relay-offload`/
  `test-offload-lifecycle`）与性能口径（`bench.sh`）。

## 决策

1. **新 crate `mini-dae/ebpf-rs`**：`aya-ebpf 0.2.1`、`no_std`、`bpfel-unknown-none`、
   `-Z build-std=core`、bpf-linker `--btf`；**不加入主 workspace**（`exclude`，避免普通
   `cargo build` 误入 BPF 目标）。构建入口 `lab/build-ebpf-rs.sh`（工具链缺失时给出安装命令）。
2. **双对象共存**：C 对象保留全部程序；`--ebpf-offload <rust.o>` 时 offload verdict 改用
   Rust 对象，其余程序仍 C。loader 同时持有两个 `Ebpf`（program/映射生命周期），
   Rust 对象里的 `fast_sock` 与 `offload_guard` 被 `take_map` 出来后由 relay 线程使用。
3. **guard 镜像**：aya-ebpf 0.2 未暴露 `SockHash` 的 lookup，而 `bpf_sk_redirect_hash`
   未命中会丢包（不能“先调再判”）。Rust 对象因此增加 `offload_guard`（普通 HASH）镜像：
   注册时 loader **先写 fast_sock 再写 guard**（反之存在 guard 命中但 fast_sock 未命中 →
   redirect 丢包的窗口）；回收时**先摘 guard 再摘 fast_sock**。
4. **计数合并**：Rust 对象自带 `mini_stats_map`（ARRAY，2=redirects，3=verdicts），
   状态面 `read_stats` 合并（0/1 仍来自 C 的 PERCPU_ARRAY）。
5. **回归口径复用**：offload 两条路线共用同一组用例与基准（`offload-up` vs
   `offload-rs-up`；`bench.sh run offload|offload-rs`），行为以 lab 回归钉住。

## 理由

- 垂直切片能在一次会话内闭环「编译 → verifier → attach → 内核对拼 → 生命周期回收」，
  把最大的未知（aya-ebpf 生成的字节码能否被 verifier 接受、与现有 loader/数据面如何共存）
  先证伪/证实，再谈全量；
- 双对象 + 镜像 map 是对 aya-ebpf API 缺口的**局部**工作区，不 fork 依赖、不打补丁；
  代价是两张 map 的双写与计数合并，都由 loader 单点维护；
- 选 offload 而非 classifier，是因为它不依赖规则 VM/双 epoch/DNS 位图，切片失败也不会
  污染主数据面。

## 后果

- 正面：数据面 Rust 路线首次全闭环并进入回归（Rust verdict 通过 verifier、内核对拼与
  连接回收全部实测通过）；工具链与构建命令化（镜像、nightly、build 脚本）；
  性能与 C 路线同量级；主 workspace 构建不受影响。
- 负面/代价：双对象与 guard 镜像是额外复杂度（aya-ebpf 上游若提供 SockHash lookup 可去掉）；
  C/Rust 两份 offload 逻辑需同步演进，靠 lab 回归约束。
- 风险：其余 7 个 classifier 与规则 VM 尚未迁移；`bpf_loop` 回调状态机、map-in-map、
  rodata 配置、`bpf_printk` 是下一批的硬点（NOTES §12）。

## 验证方式（实测）

- 环境：`rustup toolchain list` 含 nightly（1.101.0-nightly）+ rust-src；`bpf-linker 0.11.1`；
  `lab/build-ebpf-rs.sh` 产出 2.1KB BPF 对象（含 `sk_skb/stream_verdict` 段与 `maps` 段）。
- lab：`offload-rs-up` + `test-relay-offload`（512KB 内核拼接、用户态字节数远小于总传输、
  verdict/redirect 计数来自合并）+ `test-offload-lifecycle`（`active=0`、`fast_sock=0`）通过；
  C 路线同名用例与 `ss-up`（协议/offload 互斥）复测通过；`cargo test --release` 73/73。
- 性能（单次取数，方差大，量级对比）：offload-rs 11.3 Gbps·p50 19µs；
  offload(C) 同轮 8.9 Gbps·p29µs（P7 阶段另测 14.6 Gbps·23µs）。

## 修订条件

全量数据面迁移完成或改用其他机制（如 BTF map + 上游 aya-ebpf）时，新写 ADR 取代本条；
aya-ebpf 提供 SockHash lookup 后，guard 镜像与双写逻辑应删除（届时以回归确认）。
