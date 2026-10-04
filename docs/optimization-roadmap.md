# sodama 优化方向（数据驱动 · P33.2）

> 输入：`docs/perf-report.md`（2026-10-04，v2 口径：ssserver 上游 + 全双工夹具 + perf 剖面）。
> 原则：**每一条都有实测依据**，给「现状 → 目标 → 做法 → 预期收益 → 验证方式」。
> 目标：极致的吞吐/延迟 + 极致的 CPU/内存效率（不是刷分，不牺牲正确性与部署语义）。

## 优先级矩阵

| # | 方向 | 实测依据 | 预期收益 | 工作量 | 风险 |
|---|---|---|---|---|---|
| O1 | ss AEAD 零分配 + 原地加解密 | ss 剖面 AEAD ~38–41%、libc memcpy 3.4% | ss CPU -10~15% | 中 | 低 |
| O2 | ss 读写 syscall 合并/预缓冲 | 每块 2×read_exact + 2×write；`rep_movs` 中 11.7% | ss CPU -5~10% | 中 | 低 |
| O3 | relay splice 零拷贝 | relay 剖面 `rep_movs` 49.4% + 建页 18.5% | relay CPU -50% 或吞吐 ×1.5+ | 中高 | 中 |
| O4 | 每连接线程 → epoll worker 池 | 64 并发 = 100 线程、~135KB/conn；ss 4→8 流 CPU 翻倍 | 线程 O(核数)；万级连接 | 高 | 中 |
| O5 | bpf_printk 门控 | direct 剖面 0.3–0.45% 纯开销；高 PPS 放大 | 高 PPS 下显著 | 低 | 低 |
| O6 | AES-GCM 方法优先（可选） | chacha20-poly1305 AVX2 ~1.5GB/s/core | ss CPU -30~50%（若节点支持） | 中 | 低 |
| O7 | UDP 批量（recvmmsg/sendmmsg） | UDP 路径未同口径压测（backlog G1 缺口） | PPS 提升、CPU 降 | 中 | 低 |
| O8 | 缓冲池/回收与 shutdown 收敛 | 每连接 64KB 缓冲 malloc；SIGTERM 收敛 1–3s | 内存更稳、退出更快 | 低 | 低 |

---

## P0 · ss 用户态加密环路（主战场）

现状：ss 路径 8×64MB 饱和 ~10.9 Gbps；4→8 流 CPU 从 850ms → 1690ms，只换 +10%
吞吐（155 ms/Gbps）；同口径 CPU 比 dae 高 28%（590ms vs 460ms）。剖面显示没有
单一大锁，是「AEAD + 拷贝 + 逐块分配 + syscall」的叠加。

### O1 · AEAD 零分配 + 原地加解密

- **现状**：`ss.rs` 每块 `seal()` 分配 2 个 `Vec`（长度块 + 载荷），`open()` 再分配
  1–2 个；8 流下 libc memcpy/memmove 占 3.4%，分配器与页抖动混在内核 `clear_page`
  等 ~5% 中；AEAD 本体 ~38–41%。
- **目标**：每连接每方向一个可复用的缓冲（64KB+），块级加解密全部**在原地**进行，
  热路径零堆分配。
- **做法**：
  - 写：`ChaCha20Poly1305::encrypt_in_place`（`aead` crate）直接加密进复用缓冲；
    长度块(2B)与前缀帧头就地拼进同一缓冲，`write_all` 一次发出（配合 O2）。
  - 读：`decrypt_in_place_detached` / `decrypt_in_place` 在预读缓冲上解密；
  - 复用缓冲挂到 `SsReader/SsWriter` 生命周期（每连接一份，连接池化则随连接复用）；
  - SS2022 的首包头拼接同样改为就地写。
- **预期收益**：ss CPU -10~15%，垃圾分配率显著下降。
- **验证**：`perf record` 复测 chacha/poly 与 libc/malloc 占比；`scaling.sh ss`
  CPU/Gbps 曲线应单调改善（155 → ≤130 ms/Gbps）。

### O2 · 读写 syscall 合并 / 预缓冲

- **现状**：`write_classic` 每块 2 次 `write_all`（长度块、载荷）+ `flush`；
  `read_chunk_classic` 每块 2 次 `read_exact`（18B、len+16B）。剖面中
  `SsReader::read_exact` 4.8% + `pump` read 6.9% 的 `rep_movs` 均为 16KB 块级读写。
- **目标**：每 ~64KB 最多 1 次写 syscall、1–2 次读 syscall。
- **做法**：
  - 写：`seal` 进单一缓冲后一次 `write_all`（或 `writev` 两段）；批量 4 块再 flush
    一次（SS classic 块上限 16KB，一次 64KB 恰好 4 块）；
  - 读：`BufReader` 风格预读（一次 `read` 最多 64KB），在内存里解析长度/载荷块；
    保留 `pos/limit` 以支持跨 read 的半块；
- **预期收益**：ss CPU -5~10%；syscall 次数降 ~4×。
- **验证**：`perf` 中 syscall/`__check_object_size`/`rep_movs` 占比下降；
  `strace -c -p` syscall 次数对照。

### O6 · AES-GCM 路径（可选，视节点能力）

- **现状**：chacha20-poly1305 AVX2 在本平台约 1.5 GB/s/core（占 ss CPU ~40%）。
- **目标**：在有 AES-NI + CLMUL 的 x86 上，AES-256-GCM（如 `aes-gcm` crate 或
  `ring`）通常为 2–3×；ss 节点支持时优先协商 aes-256-gcm。
- **做法**：配置/订阅侧对节点方法排序；`ss.rs` 已有 aes-gcm 支持（验证其批处理
  路径是否走 AES-NI）；给出「方法 → 预期 CPU」对照表。
- **预期收益**：ss CPU -30~50%（受节点方法约束）。
- **验证**：同一四方对比改用 aes-256-gcm 方法复测（python/ssserver 均支持）。

---

## P1 · relay / 直连用户态泵：零拷贝

### O3 · splice（socket↔socket via pipe）

- **现状**：relay 路径 8 流 CPU 1.1s 换 15 Gbps；剖面 `rep_movs` 49.4% +
  `clear_page` 18.5% ≈ 68% 是「拷贝 + 建页」。这是用户态泵的结构性成本。
- **目标**：无加密直通路径几乎零用户态拷贝，CPU/Gbps 降 2× 以上。
- **做法**：
  - 每方向 `splice(client_sock → pipe)` + `splice(pipe → upstream_sock)`，
    非阻塞 + epoll 驱动，pipe 大小 `F_SETPIPE_SZ` 调大；
  - 不可 splice（非 TCP / QUIC / 需要嗅探改写）时回退现泵；保留 counters；
  - 与 eBPF offload（fast_sock）互补：offload 优先，splice 兜底第二档，
    用户态泵最后。
- **预期收益**：relay 吞吐 15 → 25+ Gbps 或 CPU 减半；直接改善「relay 路径
  24.7 Gbps（历史）→ 对齐 direct」的差距。
- **验证**：`scaling.sh relay` 对照；`perf` 中 `rep_movs` 应显著下降。

### O8 · 缓冲池与回收

- **现状**：每连接泵缓冲 `vec![0u8; 65536]` ×2 每次 malloc；峰值 64 并发连接
  100 线程、+8.6MB（~135KB/conn）；SIGTERM 优雅退出需 1–3s。
- **做法**：泵缓冲从连接级 `Vec` 改为线程本地池（一次分配，连接间复用）；
  输出路径 shutdown 时主动唤醒阻塞在 read 的泵线程（`shutdown(2)` 已可），
  收敛退出路径的有界等待（≤500ms）。
- **预期收益**：连接风暴下分配抖动更低；退出可预期。

---

## P2 · 线程与规模模型

### O4 · epoll/io_uring worker 池替代「每连接线程」

- **现状**：每个 relay 连接 1 个 accept 转交线程 + 1–2 个泵线程 + 条件性看门狗；
  64 并发已到 100 线程；连接建立/拆除的 spawn/join 成本也计入 ss RTT（p50 46µs）。
- **目标**：线程数 O(核数)（8–16），10k 并发连接稳定；每连接内存再降。
- **做法**：
  - 单事件循环（或每核 1 个）注册「poll 半边 + 目标 socket」的 EPOLLIN/EPOLLOUT；
  - 连接状态机（含半关闭、offload 看门狗、janitor）收进状态表；定时器统一；
  - 保持现有 eBPF accept/重定向语义不变（只改用户态转发引擎）；
  - 路线：先 epoll（手写，无新重依赖），后续评估 io_uring（收益需实测，
    历史 ADR-0022 提示可能被内核 offload 稀释）。
- **预期收益**：万级连接可行；小包 RTT/新建速率改善；内存更可控。
- **验证**：新增连接压力基准（新建/s、512/4096 并发 RSS 与吞吐）。

---

## P3 · eBPF 纯开销清理

### O5 · bpf_printk 门控

- **现状**：`sodama0peer_ingress`（每包）与 `sodama0_ingress`（每包）无条件
  `bpf_printk!`；direct 系统级剖面 0.3–0.45%（ss 剖面 0.45%）。当前不致命，
  但随 PPS 放大（trace ring buffer 写入 + `bpf_bprintf_prepare`），且污染
  trace_pipe。
- **做法**：改为 debug map 门控（查 1 次 map，仅 debug 打开时打印），或直接删除
  非必要行；错误路径 printk 保留。
- **预期收益**：高 PPS 直连场景 1–3% CPU；消除日志噪音。
- **验证**：`perf report | grep bpf_bprintf` 归零；64×1MB direct 吞吐复测。

---

## P4 · 协议面（后续迭代）

- **O7 · UDP**：`recvmmsg/sendmmsg` 批量收发 + per-CPU 会话表；同口径四方对拍
  （backlog G1 缺口）。
- **DNS**：命中缓存路径的 syscall 数、并发上限；已独立线程，当前不是瓶颈
  （idle 11 线程、27MB）。
- **半关闭/关闭语义**：随 O4 状态机统一处理（当前 offload 看门狗 10s 有界）。

---

## 非目标（防止走偏）

- 不为刷分绕过 redirect/tproxy/offload 语义（如伪造直连、跳过嗅探）；
- 不牺牲内存优势换吞吐：当前 28.6MB 是对手的 40–53%，任何改造保持同一量级；
- 不在 direct 路径做无谓用户态优化（CPU≈0，瓶颈在夹具/客户端）；
- 不引入重量级异步运行时除非 O4 实测收益成立。

## 验收方式（复用现有 harness）

```bash
sudo SS_UPSTREAM=ssserver ROUNDS=5 lab/perf/run.sh all   # 四方对比不回退
sudo lab/perf/scaling.sh all                             # ss CPU/Gbps 曲线改善
sudo lab/perf/run.sh down
perf record -F 1499 -g -p <sodama> -- sleep 12           # 热点搬家（AEAD→? 拷贝→?）
```

目标基线（2026-10-04）：ss 8 流 10.9 Gbps / 155 ms·Gbps⁻¹ → **≥12 Gbps / ≤110**；
relay 8 流 15.0 Gbps / 1100 ms → **≥22 Gbps / ≤550 ms**；四方对比 ss 吞吐力争
超 dae、逼近 sing-box，CPU 回到 dae 同级（≤460ms）。
