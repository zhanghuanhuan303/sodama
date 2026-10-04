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
2. **N = 核数/2（clamp 2–8）个 worker**，各持独立 epoll + eventfd 唤醒；新会话经
   `mpsc` 投递到 worker，`LOCATIONS` 表记录 session→worker 归属。
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
  stage 1 仅覆盖 splice 链路（rustls/reality/ss/vmess 仍是每连接线程）；
  prelude/非阻塞切换时序是最易回归点（回归用例需覆盖 VLESS 首包与半关闭）。
- 需警惕：offload 会话不交 reactor（两套生命周期）；worker 循环内不得在 `epoll_wait`
  期间持锁（会阻塞其它线程的 `resume`/`kill`）；`SODAMA_NO_REACTOR=1` 保留用于 A/B 与排障。

## 验证方式

- 规模（`lab/scale`，direct 拨号 → epoll 回显，hold 峰值采样）：

  | 指标 | 线程模型 | reactor |
  |---|---|---|
  | hold 10 000 | 20 011 线程 / 763 MB、5.16 s（1 938/s） | **20 线程 / 30.2 MB**、2.09 s（4 785/s）、fail=0 |
  | hold 5 000 / 1 000 | 10 011 / 2 011 线程 | 20 / 20 线程 |
  | churn 10 s | 20 860 连接/s（41 线程） | **25 974 连接/s**（32 线程） |

- 吞吐 A/B（同二进制、vless 明文、3 轮均值）：1/2/4/8 流 8 540 / 15 761 / 17 031 / 16 151 Mbps
  vs `SODAMA_NO_REACTOR=1` 8 657 / 14 890 / 16 428 / 15 706——大流不回退（1 流 −1.4% 为噪声），
  64×1 MB **15 783 vs 13 221 Mbps（+19%）**；relay 64×1 MB **37 969 vs 13 647 Mbps**；
- kTLS + reactor：8×64 MB vless-tls **10 928 Mbps 逐字节一致**、splice 错误 0；
- 回归：`cargo test --release` 240/240；lab `verify` 9/9；`test-relay` / `test-relay-idle` /
  `test-offload-lifecycle` / `test-relay-offload` 全 PASS；半关闭逐字节 verify=ok；
- stage 2（未含）：rustls/ss/vmess 会话接入同一状态机、offload 看门狗/定时器统一、
  io_uring（IORING_OP_SPLICE + 注册缓冲）A/B；UDP 批量化属 O7。

## 相关

- 实现：`loader/src/reactor.rs`（worker 池/会话状态机/prelude）、`loader/src/main.rs`
  （`handle_relay_conn` 接入、`relay_finish` 收尾）、`loader/src/outbound.rs`
  （`DialedStream.splice_prelude` 能力位）；
- 夹具/基准：`lab/scale/`（echo_server / conn_scale / run.sh）、`lab/perf/scaling.sh`（A/B）；
- 文档：`docs/vless-proposal.html` 06b 节（M4）、`docs/optimization-roadmap.md` O4。
