# I3 · 转发原语对照与选型（splice / copy / io_uring / MSG_ZEROCOPY）

> 对应评审提案 `2026-10-05-adoption-proposal.md` §I3：splice vs userspace copy vs io_uring（复测）
> vs MSG_ZEROCOPY（调研可行性与边界），维度含吞吐、CPU、p99、RSS、fd、内核对端内存（接 I1）。
> 日期：2026-10-05；状态：已完成。

## 0. 结论

| 场景 | 选型 | 依据 |
|---|---|---|
| **默认（高吞吐/大流/稳态）** | **splice（pipe 直连，零拷贝）** | 吞吐 +31~38%、CPU −80~84%（vs 用户态泵）；内核对端（pipe 页按需）可控 |
| **fd 高压（`fds_used ≥ 80% soft limit`）** | 新会话自动降级 **userspace copy pump**（I2(d)） | 每连接 4 fd → 2 fd；吞吐换可用性，已在 status 暴露回退计数 |
| **低时延/小流** | 维持 splice（无回退） | p50 无显著差异；小流由 reactor 批量搬运摊薄 syscall |
| **io_uring** | **不引入**（维持 ADR-0058） | A/B 在噪声内；第二套事件后端/取消语义成本高 |
| **MSG_ZEROCOPY** | **不适用本数据面**（仅记录边界） | 语义是「用户页→TCP 发送」，代理路径字节不在用户页；kTLS 路径已由 splice 零拷贝覆盖 |

## 1. splice vs userspace copy（同二进制 A/B）

| 口径 | splice | copy（`--no-splice`） | 差异 |
|---|---|---|---|
| M1（4×48 MB，vless，历史） | 15 8xx Mbps / CPU ~70 ms | 12 9xx Mbps / ~350 ms | **+38% 吞吐 / −84% CPU** |
| I2 复测（4×48 MB，vless，2026-10-05） | **16 851 Mbps / 70 ms** | 12 903 Mbps / 350 ms | **+31% / −80%** |
| 64×1 MB（ADR-0058 记录） | 15 783 vs 13 221 Mbps | — | +19% |
| relay 64×1 MB（ADR-0058 记录） | 37 969 vs 13 647 Mbps | — | +178% |

CPU 口径为被测进程 `utime+stime`；splice 后数据面已接近内存带宽/syscall 下限。

## 2. io_uring（IORING_OP_SPLICE）复测

- 夹具：`lab/perf/iou-splice-ab.c`（producer→relay→sink 全 loopback，1 MiB 管道，单流 64 MB，交叉配对多轮取中位）；
- 历史结论（ADR-0058）：epoll 1 MB **8.11 GB/s** vs io_uring `IORING_OP_SPLICE` 1 MB **8.18 GB/s**（+0.9%，噪声内）；64 KB 管道 io_uring 仅 4.5 GB/s；
- 复测（2026-10-05，同夹具同口径）见下节运行记录；结构性结论不变：
  1. `IORING_OP_SPLICE` 无用户注册缓冲语义（管道页内核管理），不存在「注册省拷贝」收益；
  2. 收益噪声内，代价是第二套事件后端与取消/错误语义、内核配置依赖；
  3. 维持 **不引入**。

**复测运行记录**（`bash lab/perf/m2ab.sh` 无关；直接运行 `build/iou-splice-ab`）：见 `§5 复测输出`。

## 3. MSG_ZEROCOPY 可行性（调研结论，不实现）

`MSG_ZEROCOPY`（Linux ≥4.14）的语义与适用边界：

1. **仅 TCP send 方向**：把用户态页 pin 住交给 NIC/内核发送，完成后经 `SO_EE_ORIGIN_ZEROCOPY` 错误队列回收通知；
2. **只省「用户→内核」这一份拷贝**：要求字节**位于用户态缓冲**；
3. 在本项目透明 TCP 转发路径中，字节来自**对端 socket**，不在用户态缓冲：
   - 若 recv 到用户态再 `send(MSG_ZEROCOPY)`：链路仍需
     `内核(socket) → 用户缓冲 → 内核(skbs)` 两份拷贝中的第一份（recv），
     净收益为零/为负，且引入页 pin/unpin、错误队列回收、可分片语义（小包反而更差）；
   - splice 路径为 `socket → pipe → socket`，**零份用户态拷贝**，严格占优；
4. **kTLS 路径**（M2）：加密在内核完成，明文/密文都在内核页内，splice 同样零拷贝；
   用户态 TLS（rustls）路径若改为「用户态明文 → MSG_ZEROCOPY 发送」也仍需 AEAD 处理，
   不构成零拷贝，且 M2 已实测 kTLS 相对 rustls 有明显 CPU 收益（维持默认 kTLS 可用性探测）。
5. 结论：**不引入 MSG_ZEROCOPY**；若未来出现「用户态缓冲直接构造发送流」的新协议路径
   （如 in-process 生成数据），可作为该路径的局部优化再评估。

## 4. 三档选型（落地参数）

| 档位 | 触发 | 行为 | 观测 |
|---|---|---|---|
| 吞吐优先（默认） | `fds_used < 80%·soft` | reactor splice（pipe 懒建/worker 缓存/空闲释放） | `relay.splice_fd_budget=0`，`pipe_reused` 增长 |
| fd 高压 | `fds_used ≥ 80%·soft`（1 s 缓存判定） | 新会话 `splice=false` → 用户态 copy pump（2 fd/连接） | `relay.splice_fd_budget++`，`fds_used/limit` |
| 低时延 | 小流/交互 | 同默认（reactor 批量 + 非阻塞轮转）；p50 无回退 | M1 p50 对照 |

## 5. 复测输出

2026-10-05 复测（同夹具，单流 64 MB，5 轮取中位）：

| 模式 | 吞吐中位 | 范围 | 备注 |
|---|---|---|---|
| epoll + splice（1 MiB 管道，基线） | **8.08 GB/s** | 7.76–8.25 | 与本项目 reactor 同构 |
| io_uring `IORING_OP_SPLICE`（1 MiB） | **8.15 GB/s** | 7.47–8.97 | +0.9%，噪声内 |
| io_uring + SQPOLL（`uring-poll`） | 8.50 GB/s | 8.35–8.70 | 忙等占核，系统总成本不消失，且需 CAP/内核参数 |
| io_uring 64 KB 管道 | 4.26 GB/s | 3.85–4.69 | 每字节 enter 成本上升，明显更差 |

结论：与 ADR-0058 一致——**收益在噪声内，维持不引入**；基准源码与输出留档（`lab/perf/iou-splice-ab.c`）。
