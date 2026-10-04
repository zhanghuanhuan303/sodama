# ADR-0058：M4 reactor——epoll worker 池接管 splice 链路（每连接 0 线程）

- **状态**：已采纳（2026-10-05）
- **对应决策点**：M4（`docs/vless-proposal.html` 提案）
- **相关**：ADR-0003（relay 专用 OS 线程；tokio 仅 QUIC 桥接）、ADR-0057（Vision-over-TLS）、`docs/optimization-roadmap.md` O4

## 背景

- 每连接线程模型在规模下不可接受：`lab/scale` 实测 hold 10 000 连接 =
  **20 011 线程 / 763 MB RSS**、建立 5.16 s（1 938/s）——线程与内存随连接线性膨胀，万级不可行；
- M4 评估结论（2026-10-04）：worker 化买的是**规模/风暴/内存**，不是峰值吞吐
  （splice 后数据面 CPU 已近 syscall/内存带宽下限）；
- M4 验收口径：**线程数 O(核数)**、1 万并发连接稳定建立（`hold 10000` 无失败）、
  风暴（新建/s）与吞吐不回退。

## 决策

1. **epoll worker 池只接管字节透明链路**：`splice == true` 且未 offload 的会话
   （Direct / VLESS 明文 / kTLS 成功的 TLS）提交 reactor；rustls/reality/ss/vmess 等
   仍走线程模型（stage 2 再迁）。开关：`SODAMA_NO_REACTOR=1` 回退，`SODAMA_REACTOR_DEBUG=1` 详细日志。
2. **N 个 worker**，各持独立 epoll + eventfd 唤醒；新会话经 `mpsc` 投递到 worker，
   `LOCATIONS` 表记录 session→worker 归属。stage 1 取核数/2（clamp 2–8）；stage 2 起改为
   **完整并行度**（clamp 2–16）——codec 会话是 CPU 密集（TLS/AEAD），需要压满全部核
   （本机 16 线程 → 16 worker，常驻线程 +8）。
3. **每会话两方向状态机**（`Dir{src,dst,pipe,pending,eof}`）：splice 管道 1 MB
   （`F_SETPIPE_SZ`）、块 1 MB、高水位 1 MB；EOF → `shutdown(dst, SHUT_WR)`（半关闭语义与旧泵一致）；
   两方向 done → 统一收尾（摘 `RELAY_CONNS` + 活跃计数递减）。
4. **prelude 机制**：需要消费响应头前缀的链路（VLESS）不在 reactor 内同步做——
   reactor 先接管上行、暂停下行；短命线程用 codec 读半消费响应头并写给客户端，完成后
   `resume(id)`（切非阻塞 + 恢复下行）；失败 `kill(id)`。Direct（无前缀）直接进入批量搬运。
5. **非阻塞切换时机**：`SPLICE_F_NONBLOCK` 只作用于**管道端**，socket 端是阻塞的；
   必须先对两个 socket `set_nonblock` 才能循环搬运到 EAGAIN，否则第二次 splice 真阻塞 worker。
   prelude 完成前不得切换（读半与 prelude 共享同一 file description，会污染 codec 读半）。
6. **kTLS 迟到控制记录**：内核 RX 上迟到的 NewSessionTicket 会让 splice 返回 EINVAL
   （非致命）——复用 `ktls_take_control_record` 消费后重试；普通 socket 上该调用不误吞数据。

## 理由

- 事件循环把「每连接 2 个 OS 线程」变成「每连接一个状态条目」，线程/内存不再随连接数增长；
  实测 10k 连接线程 ≈1/1000、RSS ≈1/25，同时建立速率与风暴吞吐反升（见验证）；
- 大块 splice + 非阻塞轮转不改变数据面字节路径，吞吐 A/B 无回退，小流/多连接场景还受益
  （管道批量搬运摊薄 syscall 与调度成本）；
- 不引入 async 运行时（沿用 ADR-0003）：IO 多路复用手写 epoll 即够，避免把数据面搬进 tokio。

## 后果

- 正面：万级连接可行且内存可控；连接风暴吞吐提升；为后续 io_uring A/B 留下骨架。
- 负面/代价：数据面出现一条并行路径（reactor + 线程泵），维护与回归面变大；
  reactor 现覆盖 splice 链路 + codec 首段（rustls VLESS-TCP/Trojan），
  reality/vision/ws/ss/vmess 仍是每连接线程（stage 2 余段）；
  prelude/非阻塞切换/预算补泵是最易回归点（回归用例需覆盖 VLESS 首包、半关闭与长尾流）。
- 需警惕：offload 会话不交 reactor（两套生命周期）；worker 循环内不得在 `epoll_wait`
  期间持锁（会阻塞其它线程的 `resume`/`kill`）；`SODAMA_NO_REACTOR=1` 保留用于 A/B 与排障。

## 验证方式

- 规模（`lab/scale`，direct 拨号 → epoll 回显，hold 峰值采样）：

  | 指标 | 线程模型 | reactor |
  |---|---|---|
  | hold 10 000 | 20 011 线程 / 763 MB、5.16 s（1 938/s） | **28 线程 / 32.1 MB**、2.12 s（4 717/s）、fail=0 |
  | hold 5 000 / 1 000 | 10 011 / 2 011 线程 | 28 / 28 线程 |
  | churn 10 s | 20 860 连接/s | **25 606 连接/s**（40 线程） |

- 吞吐 A/B（同二进制、vless 明文、3 轮均值）：1/2/4/8 流 8 540 / 15 761 / 17 031 / 16 151 Mbps
  vs `SODAMA_NO_REACTOR=1` 8 657 / 14 890 / 16 428 / 15 706——大流不回退（1 流 −1.4% 为噪声），
  64×1 MB **15 783 vs 13 221 Mbps（+19%）**；relay 64×1 MB **37 969 vs 13 647 Mbps**；
- kTLS + reactor：8×64 MB vless-tls **10 928 Mbps 逐字节一致**、splice 错误 0；
- **回归**：`cargo test --release` **246/246**（新增响应头/帧头/写半 WO 可重入用例）；lab `verify` 9/9；
  `test-relay` / `test-relay-idle` / `test-offload-lifecycle` / `test-relay-offload` 全 PASS；
  半关闭逐字节 verify=ok；vision 夹具 tls/reality/ws/wss 全过；
- stage 2 余段（未含）：ss/ssr/anytls 会话接入（读半/写半需同模式改造）、
  offload 看门狗/定时器统一、io_uring（IORING_OP_SPLICE + 注册缓冲）A/B；UDP 批量化属 O7。

## stage 2：codec 会话接入（VLESS 全组合 + Trojan + vmess）

- **机制**：非 splice 且已审计的链路交 `submit_codec`——每方向 `CodecSide`（Sink=写半加密 /
  Source=读半解密）在 worker 内非阻塞驱动；`out` 缓冲 128 KB 水位 / 64 KB 块；
  EPOLLIN/EPOLLOUT 由「读侧可读 / 写侧可写」计算；EOF 后经写半 `shutdown_write` / 对端 `SHUT_WR` 半关闭；
  协议面由 `Outbound::codec_reactor_capable()` 判定：**Trojan、VLESS 全组合（Tcp/Ws ×
  明文/rustls/REALITY/±vision）与 vmess**；ss/ssr/anytls 等仍走线程模型。
- **可重入前提（本项核心修复）**：
  1. `TlsWriter::write`：rustls `writer().write` 只入缓冲（0.23 语义，永不 WouldBlock），
     `write_tls` 遇 WouldBlock 必须在已消费后降级为「待刷」（否则重试会重复加密/发送）；
     `flush()` 上抛 WouldBlock，由状态机等 EPOLLOUT 重试；
  2. 读半可重入：`VlessReader` 响应头缓冲累积、`VisionReader` 帧头游标 `hdr_got`、
     `WsReader` 改「ensure_buffered + 缓冲解析」（含控制帧 `pending_control` 续读）；
     `Tls13Reader` 原 `pending` 续读、`VmessReader` 原缓冲+游标均满足；
  3. 写半待刷队列：`Tls13Writer`/`VisionWriter`/`WsWriter`/`VmessWriter` 均改为
     「组帧/密封入队 + 部分写 + WO 断点续写」，重试不重复组帧；
  4. **预算耗尽自驱补泵**：pump 每事件限 8 轮，可能在「rustls 内部已有明文、内核无事件」时退出
     （卡住时两侧 pending=0、interest 挂着 EPOLLIN）；修复：会话入 worker `pending` 队列，
     事件循环空转时继续泵，直到无内部余量。stress 45 轮（4/8/64 流）0 失败，补泵触发 1.7 万次；
  5. **终止帧幂等**（vmess）：非阻塞下 `send_terminator` 会被反复重试，若每次重试都重新入队
     终止帧，`pending` 会无界增长（实测把测试进程撑到 20GB 被 OOM）；改为「终止帧只入队一次 +
     续写断点」，并把 reactor 的 `shutdown_write` WO 处理改为「不置 done、等 EPOLLOUT 重试」。
- **开关**：`SODAMA_REACTOR_CODEC=0` 关闭 codec 入池（回退线程模型）；
  `SODAMA_REACTOR_DEBUG=1` 含会话状态周期转储（诊断卡尾用）。
- **实测（vless-tls，同二进制 A/B）**：1/2/4/8×64MB 吞吐 6.1 / 9.1–10.4 / 11.7–12.5 / 10.5–10.9 Gbps
  vs 线程模型 5.4 / 8.1 / 10.9 / 9.9（+5~25%）；64×1MB 在轮间噪声内（两模式 8.3–15.3 Gbps）；
  长连接持有 2 000 条 = **27 线程 / 61 MB**（线程模型 4 011 线程 / 222 MB）、fail=0、建立 1 010/s；
  **vision 夹具 tls/reality/ws/wss 四模式逐字节全过（ws/wss 亦走 codec，0 错误）**；
  **reality+vision 60 个并发 HTTPS 下载下 reactor 恒定 27 线程**；vmess/ws/vision 写半均有 WO 注入单测。

## 相关

- 实现：`loader/src/reactor.rs`（worker 池/会话状态机/prelude/codec 泵与自驱补泵）、`loader/src/main.rs`
  （`handle_relay_conn` 接入、`relay_finish` 收尾、`submit_codec` 分支）、`loader/src/outbound.rs`
  （`DialedStream.splice_prelude`、`codec_reactor_capable`）、`loader/src/tls.rs`/`vless.rs`
  （WouldBlock 可重入）；
- 夹具/基准：`lab/scale/`（echo_server / conn_scale / run.sh）、`lab/perf/scaling.sh`（A/B）；
- 文档：`docs/vless-proposal.html` 06b 节（M4）、`docs/optimization-roadmap.md` O4。
