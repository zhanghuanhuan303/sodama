# ADR-0025：移除 C 数据面（单一 Rust 对象，回退即重建）

- **状态**：已采纳（2026-10-04）
- **对应**：ADR-0002「先 C 后迁」的收尾；P9（ADR-0024）默认切换后的必然清理
- **相关**：ADR-0002、ADR-0023、ADR-0024；NOTES §11.13/§11.14/§12；mini-dae/README.md

## 背景

ADR-0022/0023/0024 之后，数据面存在两个对象：Rust 全量对象（默认加载）与 C 对象
`build/mini_dae.o`（`USE_EBPF_C=1` 回退、offload 对照）。双份实现需要同步（任一侧改动都要
维持布局与语义一致），且 C 回退只在"Rust 出问题时"才被使用——而全量回归已在 Rust 对象上
9/9 + 各专项通过。继续保留回退的成本（双份构建、双份维护、脚本分支、混淆默认值）高于收益。

## 决策

1. **删除 C 数据面**：移除 `ebpf/mini_dae.c`（整个 `ebpf/` 目录）与 `build/mini_dae.o`；
   `lab/lab.sh build` 只构建 Rust 对象（`lab/build-ebpf-rs.sh`，失败即失败，不再"跳过"）。
2. **单一对象**：lab 的 `up()`/`dual_up()` 直接加载
   `ebpf-rs/target/bpfel-unknown-none/release/mini-dae-ebpf`；删除 `USE_EBPF_RS`/`USE_EBPF_C`/
   `USE_OFFLOAD_RS` 分支，删除 `offload-rs-up`/`rs-up`/`rs-dual-up` 会话（`offload-up` 即
   Rust offload）。
3. **loader 去掉 offload 双对象**：删除 `--ebpf-offload`、`static OFFLOAD_EBPF` 与
   "从 offload 对象读 verdict/redirect 计数"的回退分支；offload 计数与数据面同属
   `mini_stats_map`（索引 2/3）。`--ebpf` 默认值指向 Rust 对象。
4. **bench/soak 同步**：bench 删除 `offload-rs` 路径（`offload` 保留）；bench/soak 的对象
   存在性检查改为 Rust 对象路径。`bench_io.c` 是压测服务端夹具，不属于数据面，保留。
5. **回退方式**：不再保留二进制回退。需要 C 对照时从只读上游 clone `dae/`
   （或历史快照）重建 C 对象，并临时改 loader/脚本指向它；这是调试手段，不是产品路径。

## 理由

- Rust 对象已经被同一套回归网（verify 9/9、DNS/转发面/协议梯/运维/soak）验收过，
  默认路径就是它；C 回退自 P9 切换后未再被任何实验依赖。
- 双份布局同步是持续的隐性成本（TCP flags 位段、map 布局、规则 VM 语义），删除后
  单点维护；`grep` 证明无残余引用后可认为清理完整。
- "回退即重建"把风险从"维护两份"转移到"可重建"：C 源在上游与 clone 中始终可得，
  重建成本是分钟级。

## 后果

- 正面：数据面代码库只剩 `ebpf-rs/`（Rust/aya-ebpf），不存在 C 实现；脚本无数据面分支；
  loader 无 offload 对象回退分支；文档/坑列表与新手的认知负担同步下降。
- 负面/代价：
  - 跑任何会话都要求 Rust eBPF 工具链（nightly + `bpf-linker` + `build-ebpf-rs.sh`）；
    工具链缺失时 `build` 直接失败（这是有意的——不再有"静默跳过 eBPF 对象"）。
  - 无现成 C 对照对象；对照需从 `dae/` clone 重建 C 版本。
  - 历史文档中 `USE_EBPF_C=1` 的描述仅具史料意义（明确标注）。
- 风险：若未来需要与上游 C 实现做逐字节布局对拍，需重建 C 对象（源可得，风险低）。

## 验证方式（实测）

- 构建：`lab/lab.sh build` 全绿（loader 零 warning；Rust 对象 274KB，含 `.BTF`）。
- 残余检查：`grep -rn "mini_dae\.c\|mini_dae\.o\|USE_EBPF\|USE_OFFLOAD_RS\|offload-rs\|ebpf-offload"`
  在 `lab/`、`loader/src/`、`ebpf-rs/src/` 零命中；`lab/lab.sh rs-up`/`offload-rs-up` 退出码 2（usage）。
- 回归（唯一 Rust 对象）：
  - 标准拓扑 verify **9/9**；单臂 `dual-up` verify **9/9**（本次串行执行无 flake）；
  - 抽查：`test-domain`（DNS）、`test-forward`（转发面一跳）、`test-ss`（协议栈）全 PASS；
  - `cargo test --release` **73/73**；
  - `lab/bench.sh run offload`：12.4Gbps / p50 19µs（offload 路径工作正常，无 offload-rs）；
  - `lab/bench.sh all` 六路径（单次取数；与 P7 C 时代同口径口径）：direct 30635Mbps/10µs、
    relay 23780/18µs、offload 7503/24µs（同对象三次单跑 12437/19µs、8286/30µs——**单次方差大**，
    量级仍与 C 同档）、ss 2452/59µs；UDP blast 丢包 11262/11220——与历史 C 同数值，端点丢包主导；
  - **P9+ 完整性回归（2026-10-04）**：DNS 6/6、转发面 6/6、K3/运维 5/5、协议梯 15 个会话
    **17/17 端到端**（含 vless/vmess TLS 变体）；`parity.sh` IP 规则 **5/5 逐字节一致**
    （rules.dae/reload/udp/fault/bench；rules.dns/regex 因 Go 侧 dump 工具
    `unhandled match type 0` 不在对拍范围内——工具既有限制）；`proto-check` vmess/none、
    vmess/tls、vless/none **3/4 PASS**（vless/tls 为 P5 已知的 Go 客户端 `allowInsecure` 偏差，
    Rust 侧 TLS 由 lab e2e 覆盖并通过）；soak tcp60/ss30/udp30 无泄漏；内核矩阵
    双内核 9/9（宿主 6.18.54-2-lts 与 QEMU 7.2.8-arch1-2，MATRIX-RESULT verify=PASS）；
    详见 NOTES §11.16 与 `lab/matrix/SUMMARY.md`。
- 环境清洁：无遗留 mini-dae 进程与 netns；`dae/` clone `git status --porcelain` 为空。

## 修订条件

- 若需要与上游 C 数据面对拍（如规则 VM 语义调查），从 `dae/` 重建 C 对象并临时切换
  `--ebpf` 指向；实验结束后按本 ADR 恢复单一 Rust 对象。
- 若 Rust 数据面出现回归且无法快速修复，可在临时分支恢复双对象（参考 ADR-0023/0024 的
  `USE_EBPF_C` 机制），但默认路径仍应回到单一 Rust 对象。
