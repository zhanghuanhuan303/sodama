# sodama 优化方向（数据驱动 · P33.2）

> 输入：`docs/perf-report.md`（2026-10-04，v2 口径：ssserver 上游 + 全双工夹具 + perf 剖面）。
> 原则：**每一条都有实测依据**，给「现状 → 目标 → 做法 → 预期收益 → 验证方式」。
> 目标：极致的吞吐/延迟 + 极致的 CPU/内存效率（不是刷分，不牺牲正确性与部署语义）。

## 优先级矩阵

| # | 方向 | 实测依据 | 预期收益 | 工作量 | 风险 |
|---|---|---|---|---|---|
| O1 | ss AEAD 零分配 + 原地加解密 | ss 剖面 AEAD ~38–41%、libc memcpy 3.4% | ss CPU -10~15% | 中 | 低 |
| O2 | ss 读写 syscall 合并/预缓冲 | 每块 2×read_exact + 2×write；`rep_movs` 中 11.7% | ss CPU -5~10% | 中 | 低 |
| ~~O3~~ | ~~relay splice 零拷贝~~ **（M1 已完成）** | relay 剖面 `rep_movs` 49.4% + 建页 18.5% | ✅ 实测：relay 8 流 14.9→**21.6 Gbps**、CPU 1100→**150ms**；vless 明文 12.2→**16.9 Gbps**、CPU 380→**60ms** | — | 已交付（`--no-splice` 可关） |
| O4 | 每连接线程 → epoll worker 池 | 64 并发 = 123 线程、~175KB/conn | 线程 O(核数)；万级连接 | 高 | 中 |
| ~~O5~~ | ~~bpf_printk 门控~~ **（M1 已完成）** | direct 剖面 0.3–0.45% 纯开销 | ✅ 默认关：单次传输 trace 600+→**0 行**；`--ebpf-debug` 开 | — | 已交付 |
| O6 | AES-GCM 方法优先（可选） | chacha20-poly1305 AVX2 ~1.5GB/s/core | ss CPU -30~50%（若节点支持） | 中 | 低 |
| O7 | UDP 批量（recvmmsg/sendmmsg） | UDP 路径未同口径压测（backlog G1 缺口） | PPS 提升、CPU 降 | 中 | 低 |
| O8 | 缓冲池/回收与 shutdown 收敛 | 每连接 64KB 缓冲 malloc；SIGTERM 收敛 1–3s | 内存更稳、退出更快 | 低 | 低 |
| ~~O9~~ | ~~kTLS 内核 TLS + TLS 上 splice~~ **（M2 已完成，实验开关）** | TLS 剖面 memcpy 29.4% + 建页 | ✅ 实测：48MB×4 中位 11.67→**12.32 Gbps**、CPU 420→**400ms**、memcpy→**1.6%**；8 流受同机夹具/内核 AES 速度限制（详见提案 05/07 节） | 中 | 中（需 TLS1.3+modprobe tls；默认关） |

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

### O6 · AES-GCM 方法优先（可选，视节点能力）

- **现状**：chacha20-poly1305 AVX2 在本平台约 1.5–2.9 GB/s/core（M2 实测：用户态 2.87 GB/s、内核 1.76 GB/s）。
- **实测（M2 复测）**：AES-128-GCM 本机用户态 **6.57 GB/s**、内核 2.89 GB/s（均 = chacha 的 2.3×/1.6×）；
  ss/vless 节点支持时应优先协商 aes-*-gcm（含 kTLS 路径）。
- **做法**：配置/订阅侧对节点方法排序；`ss.rs` 已有 aes-gcm 支持（验证其批处理
  路径是否走 AES-NI）；给出「方法 → 预期 CPU」对照表。
- **预期收益**：ss CPU -30~50%（受节点方法约束）。
- **验证**：同一四方对比改用 aes-256-gcm 方法复测（python/ssserver 均支持）。

---

## P1 · relay / 直连用户态泵：零拷贝

### O3 · splice（socket↔socket via pipe）——✅ M1 已完成（2026-10-04）

- **实测（同口径复测）**：relay 8×64MB 14 864 → **21 580 Mbps**（CPU 1 100 → 150 ms）；
  vless 明文 48MB×4 中位 12 225 → **16 926 Mbps**（CPU 380 → 60 ms）；
  perf 中 `rep_movs`+建页（≈65%）退出前十，转为内核 splice 管线（`skb_splice_from_iter` 8.4% 居首）。
- **实现**：`DialedStream.splice` 能力位（Direct / VLESS 明文 TCP）；每方向
  `splice(socket→pipe→socket)`（1MB 管道、页级，EOF→`SHUT_WR` 保持半关闭语义）；
  VLESS 请求头拨号时发出、响应头由一次 codec 首读消费后切 splice；EINVAL 自动回退旧泵；
  `--no-splice` 开关；`status`/Prometheus 暴露 `splice_total/fallbacks`（命中 720 / 回退 0）。
- **验证**：`lab.sh verify` 9/9、`cargo test` 236/236、半关闭逐字节 verify=ok。
- **遗留**：加密/成帧链路不适用（vision/ws 仍不适用；TLS 已在 O9 以 kTLS 打通）。

### O9 · kTLS（内核 TLS）——✅ M2 已完成（实验开关，2026-10-04）

- **实测**：TLS 48MB×4 中位 11 670 → **12 318 Mbps**（CPU 420 → 400 ms；p50 39→43 µs）；
  8×64MB：memcpy 29.4% → **1.6%**（达标 ≤3%），吞吐/CPU 受同机夹具封顶
  （sing-box 服务端与网关同机，四方客户端均 10.7–12.5 Gbps；系统总 CPU 两路径相同 ≈2.87 s）。
- **实现**：① 逐记录握手驱动（`handshake_record_by_record`：按 TLS 记录边界喂 rustls，
  服务端 Finished 后立即停止，post-handshake 记录全留给内核，`rec_seq` 从 0 对齐——修复 EBADMSG 根因）；
  ② KeyLog→HKDF-Expand-Label→`setsockopt(TCP_ULP/TLS_TX/TLS_RX)`（AES-128/256-GCM、chacha20）；
  ③ `ktls_read` recvmsg+cmsg 处理控制记录（NST 丢弃/alert=EOF）；
  ④ 下行 splice 遇控制记录（内核返回 EINVAL + requeue）先用 `MSG_PEEK` 核实并消费再重试（≤8 轮）；
  ⑤ kTLS 成功后 outbound 置位 splice 能力位，TLS 双向零拷贝。
- **验证**：`TlsDecryptError` 增量 0；`splice_total=4/fallbacks=0`；`lab verify` 9/9（含 `USE_KTLS=1`）、
  vless-tls/vmess-tls/trojan 均见 kTLS 启用；TLS1.2（shadowtls v1）自动回退 rustls；`cargo test` 236/236；`lab/perf/m2ab.sh` 可复现 A/B。
- **边界**：需 `modprobe tls` 与 TLS1.3；对端 KeyUpdate 会使内核 RX 拒绝解密（断连不静默丢数据）；
  **内核 AES-GCM 速度决定收益**：本机 `generic-gcm-aesni-avx` 2.89 GB/s（用户态 6.57 GB/s）故默认仍用 rustls；
  VAES/AVX-512 平台或 NIC TLS 卸载时开启 `--ktls`（详见 `vless-proposal.html` 05/07 节）。

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

### O5 · bpf_printk 门控——✅ M1 已完成

- **实现**：`control_flags` 新增 debug 位（读改写保留 suspend 位）；门控
  `flow.rs` 的 `cached`（每包）/`stateless`/`route` 与 `progs.rs` 的
  `dae0peer_ingress`/`sk_assign`/`dae0_ingress`；`--ebpf-debug` 打开。
- **实测**：默认关时单次传输 trace 行 600+ → **0**；打开时 600+（可调试）。
- **验证**：`grep -c "sodama:" /sys/kernel/tracing/trace` 前后对照。

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

目标基线（2026-10-04，M2 后更新）：vless 明文 8 流 **16.2 Gbps / 190 ms**（已达 ≥16 G 目标）、
48MB×4 中位 **16.9 Gbps / 60 ms**；relay 8 流 **21.6 Gbps / 150 ms**；
TLS：kTLS 全链路可用，48MB×4 中位 **12.3 Gbps / 400 ms**，memcpy 1.6%（达标）；
8 流吞吐/CPU 目标（≥13 Gbps/≤1000 ms）因本机夹具（同机 sing-box TLS 服务端 ≈12.5 Gbps 封顶）
与内核密码引擎速度（2.89 GB/s）均不可达——需要“服务端异机”口径后再评（M3 重测项）；
M4：ss 8 流 CPU ≤460 ms、四方对比 ss 吞吐超 dae、逼近 sing-box；线程数 O(核数)（10k 连接基准）。
