# ADR-0002：eBPF 程序语言——先 C 后迁

- **状态**：已采纳（2026-10-03）
- **对应决策点**：D2
- **相关**：ADR-0003（运行时）、`sodama/`（实测）

## 背景

数据面是 `control/kern/tproxy.c`：**4,403 行 C、23 个程序、24 个 map**。它承载分流规则 VM、conntrack、重定向、tproxy 交付、offload。Rust 侧有 `aya`（用户态）与 `aya-ebpf`（内核态）两条路径。

实测情况：

- `aya` 加载 **C 编译产物** 已验证可行（sodama：3 个 TCX 钩子、跨 netns map 共享、`bpf_sk_assign` 交付、double-path e2e 全部通过）；
- `aya-ebpf` 需要 **nightly + `-Z build-std`** 构建 `bpfel-unknown-none`；本次环境 rustup 官方源被网络策略拦截，**未验证**（`bpf-linker 0.11.1` 已装好）。

## 选项

| 选项 | 说明 |
|---|---|
| A 保持 C | 数据面继续用 clang 编译，Rust 只做加载器/控制面 |
| B 全量迁 aya-ebpf | 数据面也用 Rust 写，类型安全、与用户态共享结构体 |
| **C 先 C 后迁（采纳）** | **先用 C 对齐行为并建立基准，再逐个程序迁移并用差分测试保护** |

## 决策

采用 C。约束：

1. 数据面 ABI 由 `dae-ebpf-shared`（no_std 共享 crate）单一定义，C 侧通过生成的头文件引用 —— **不引入第三处同步**；
2. 迁移以「程序」为粒度（先 `tproxy_dae0_ingress`/`dae0peer_ingress` 这类边界清晰的，后 `route()` 这类 verifier 敏感的核心）；
3. 每个迁移都必须在 CI 的内核矩阵上通过，并且逐字节对拍 map 内容与判决结果。

## 理由

- 数据面的风险不在语言，而在 **verifier 约束与内核版本矩阵**：栈 512B、循环上界、指针收敛、`bpf_loop` 回调状态机。这些约束在 C 上已有大量注释与测试沉淀（`tproxy.c` 里成片的 per-CPU scratch、`__noinline` 拆分、栈预算注释）。
- sodama 的实测证明：**加载器用 Rust、数据面用 C** 这条组合今天就能产出可用系统（也顺带证明了 TCX 生命周期管理比 netlink 干净）。
- 迁移是**可逆且可分批**的：Rust 控制面只依赖对象文件的 section/符号约定，换实现不影响上层。

## 后果

- 正面：立即可以开始 P2；verifier 行为与 dae 完全一致，问题可归因；后续迁移有基准与对拍保护。
- 负面/代价：短期内仓库里 C 与 Rust 并存，需要一套统一的构建入口（`build.rs` 调 clang，产物 `include_bytes!` 进二进制）来消除「版本漂移」风险。
- 需要注意：C 侧结构体与 Rust 共享 crate 的布局一致性必须有编译期断言（`static_assert` / `const _: () = assert!(size_of::<T>() == N)`）。

## 验证方式

- P2 验收：同一份规则，Rust 控制面加载 C 对象后，direct/proxy/回程三路径 e2e 通过（sodama 已给出最小闭环）；
- 迁移验证：迁移前先落一份 map dump + 判决对拍基线，迁移后逐条比对。

## 修订条件

若 `aya-ebpf` 的稳定版工具链（无需 nightly）成熟，且 verifier 友好写法被验证，可以新写 ADR 把默认路径切到 Rust。
