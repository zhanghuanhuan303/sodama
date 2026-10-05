# ADR-0059：I6——会话建立零线程（in-worker prelude）与启动水位回收

- **状态**：已采纳（2026-10-05）
- **对应**：第三方评审 A5「启动水位/churn 线程峰值」的落地项（原建议延后，用户决策执行）
- **相关**：ADR-0058（M4 reactor；本 ADR 取代其中「prelude 短命线程」机制）、`docs/reviews/2026-10-05-i1-system-memory-data.md`

## 背景

1. **churn 线程峰值**：mem.sh churn 场景实测 sodama 线程峰值 **46**（稳态 28）——其中约一半来自
   `reactor::submit` 里为 VLESS 响应头「首读」按会话起的 **prelude 短命线程**，其余为会话建立
   线程（accept→dial→submit，短生命周期）。
2. **启动水位**：启动完成后（规则编译/订阅/geodata/eBPF 装载）分配器高水位留在自由链里，
   `N=0` 采样 RSS ≈ **27–28 MB**，要等 O8 的 30 s 周期 `malloc_trim` 才回落到 12 MB。
3. **会话线程栈**：relay/tproxy 入口线程用默认 8 MiB 栈；万级瞬时建立时虚拟内存可观。
   且 `std::thread::spawn` 失败会 **panic 打死分发线程**（20k 连接 / cgroup pids 撞限场景曾复现）。

## 决策

1. **prelude 迁入 worker（零线程）**：`submit` 不再为 VLESS 响应头首读起线程；会话在
   reactor 内用 `PreludeBuf` 状态机驱动：
   - 读半与 `fill` 共用同一 file description（**会话自始 O_NONBLOCK**），
     `read` 返回 WouldBlock 时等下一次 upstream EPOLLIN（`VlessReader` 自 stage 2 起可重入）；
   - **首读一次成功即完成**（与旧 prelude 线程「一次 read」语义一致），明文按部分写排队在
     `out`，等客户端 EPOLLOUT 冲刷；冲刷干净后丢弃 reader、解除 `u2c_paused` 转 splice；
   - prelude 活跃期 upstream 的 EPOLLIN 只驱动首读，不得交给 u2c splice；prelude 刚完成的
     事件内**不**主动 fill(u2c)——残留字节交给 level-triggered EPOLLIN 下一轮，保持管道懒建
     （避免 fd/连接从 4 升到 6）。
2. **启动水位**：启动完成后立即 `trim_allocator()` 一次（不等 30 s 周期）；热重载完成后同样回收。
3. **入口线程栈 1 MiB**：relay/tproxy 会话线程用 `Builder::stack_size(1 MiB)` 命名创建；
   **创建失败仅丢弃该连接并记日志**（不再 panic）。

## 理由

- prelude 的首读是「纯等待一次响应头」，把它变成每会话一个 OS 线程是线程数随 churn 上涨的
  主因；放入 worker 后该路径**每连接 0 线程**（与 reactor 目标一致），且 Reactor 的
  EPOLLIN 驱动天然批量化。
- 启动 trim 成本微秒级、只在启动/重载时调用，随即将常驻水位打到低点，对外观感与容器内存
  限额都直接受益。
- 1 MiB 栈足够覆盖 dial/handshake 调用深度（全量单测 + lab 回归验证）；失败降级为丢连接，
  避免「一个瞬时资源问题打死整条 accept 分发」。

## 后果

- **正面（实测，2026-10-05）**：
  - 启动/空闲 RSS：**26.7 → 11.1–11.7 MB**（mem.sh idle；I1 扫描 `N=0` 28.3 → 11.4 MB）；
  - churn 线程峰值：**46 → 35**（同夹具同负载：hold 2000 + churn 10 s；吞吐保持 ≈2 550 conn/s）；
  - VLESS splice 吞吐不回退：16.4/15.6 Gbps vs 16.9（I2 版本，噪声内），p50 38–40 µs，传输期线程 28；
  - fd/连接维持 **4.0（2 socket + 2 pipe）**（I1 扫描 20 k：80 087 fd）；回收后 RSS 12.5 MB。
- **负面/代价**：reactor 状态机多一个 prelude 分支（首读/部分写/事件路由），并新增两条
  开发期已修复的坑：① 首读循环读到 EOF 会长期占用 prelude（非零拷贝、会话停滞）——
  必须首读即完成；② prelude 完成后主动 fill(u2c) 会多建一条空闲管道（4→6 fd/连接）。
  这两点已写入代码注释与本节，回归用例依赖 mem-system I1 扫描（fd 断言）与 perf vless A/B。
- **保留**：`SODAMA_NO_REACTOR=1` 仍回退线程模型（prelude 亦随之回退到旧语义，不受影响）。

## 验证方式

- `cargo test --release` **257/257**；`lab.sh verify` **9/9**；
  `test-vless` / `test-relay` / `test-ss` / `test-relay-offload` / `test-offload-lifecycle` 全 PASS；
- `lab/perf/run.sh bench sodama`（vless，4×48 MB×2 轮）16.4/15.6 Gbps、p50 38–40 µs、28 线程；
- `lab/perf/mem-system.sh` 扫描 100–20 000：`N=0` 11.4 MB、20 k 活跃 28.6 MB、
  fd 4.0/连接、fail=0；
- `lab/perf/mem.sh bench sodama`：idle 11.1 MB / hold 14.3 MB（29 线程）/ churn 35 线程 /
  recovery 12.5 MB；
- `lab/perf/soak-curve.sh run 3600`（1 h，I6 版本）：曲线与漂移判据见
  `docs/memory-report-v2.html` §3.8。

## 相关

- 实现：`loader/src/reactor.rs`（`PreludeBuf` / prelude 事件路由 / 删除 `resume()`）、
  `loader/src/main.rs`（启动/重载 trim、`RELAY_HANDLER_STACK`、线程创建失败降级）；
- 数据：`docs/reviews/2026-10-05-i1-system-memory-data.md`、`docs/memory-report-v2.html`。
