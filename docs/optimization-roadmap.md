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
| ~~O4~~ | ~~每连接线程 → epoll worker 池~~ **（M4 已完成，stage 1+2 全部）** | hold 10k = 20 011 线程 / 763 MB；64 并发 = 123 线程、~175KB/conn | ✅ 实测：10k 连接 **28 线程 / 32.1 MB**、fail=0、建立 4 717/s；风暴 **25 606/s**（线程模型 20 860/s）；vless 吞吐无回退（64×1 MB +19%）；relay 64×1 MB **37.9 vs 13.6 Gbps**；**vless-tls 2 000 连接 27 线程 / 61 MB（线程模型 4 011 / 222 MB）**；**offload 200 条 0 新增线程** | — | 已交付：stage 1 splice + stage 2 codec 全协议面（VLESS 全组合含 reality/vision/ws、Trojan、vmess、ss/ssr/anytls 每连接 0 线程）+ offload 看门狗单线程化；io_uring A/B 结论不引入；`SODAMA_NO_REACTOR=1` / `SODAMA_REACTOR_CODEC=0` 可关；细节见 O4 节与 ADR-0058 |
| ~~O5~~ | ~~bpf_printk 门控~~ **（M1 已完成）** | direct 剖面 0.3–0.45% 纯开销 | ✅ 默认关：单次传输 trace 600+→**0 行**；`--ebpf-debug` 开 | — | 已交付 |
| ~~O6~~ | ~~AES-GCM 方法优先~~ **（已完成：实测结论为保留 chacha）** | 本机 RustCrypto：AES-NI 块加密 ~6 GB/s，但 GCM 受 GHASH 2.3 GB/s 串行限制（16KB 块 1.57 vs chacha 1.73 GB/s） | ✅ 测：ss TCP chacha 5.8–9.7 vs aes 4.4–8.0 Gbps、CPU 更低 → 不做 AES 优先；vmess auto→chacha、组内同分优先 chacha；定向换 ring/aws-lc 后端列为后续 | — | 已交付（微基准 `cipher_microbench` 留档；M2 6.57 GB/s 为块加密口径已更正） |
| ~~O7~~ | ~~UDP 批量（recvmmsg/sendmmsg）+ 会话表分片~~ **（已完成）** | UDP 路径未同口径压测（backlog G1 缺口） | ✅ 实现：批量收发（Plain/Ss，`SODAMA_UDP_BATCH=0` A/B）+ 16 分片会话表 + 4–8MB 转发缓冲；20k pps 0 丢包 CPU **630 ms/40k 包**（dae 2140 / sing-box 1580 / v2ray 1780），RSS 28.6MB 最小；四方对拍 `lab/perf/udp.sh` | — | 已交付；实测批量在限速下每批 ~1 包（非 syscall-bound），保留但不宣称大幅提升（详见 O7 节） |
| ~~O8~~ | ~~缓冲池/回收与 shutdown 收敛~~ **（已完成）** | 每连接 64KB 缓冲 malloc；SIGTERM 收敛 1–3s（实测回退为即杀） | ✅ `bufpool`（64/128KB、按字节封顶 8MB）+ UDP 槽按需增长 + 有界优雅退出（50 在途连接 462ms）+ 30s `malloc_trim`；churn 300 条 RSS 23.9→trim 23.3MB 无增长 | — | 已交付；附带修复 ss 帧边界 EOF 误报截断（+2 单测）；verify 的 orig_dst 夹具陈旧另记 backlog |
| ~~O9~~ | ~~kTLS 内核 TLS + TLS 上 splice~~ **（M2 已完成，实验开关）** | TLS 剖面 memcpy 29.4% + 建页 | ✅ 实测：48MB×4 中位 11.67→**12.32 Gbps**、CPU 420→**400ms**、memcpy→**1.6%**；8 流受同机夹具/内核 AES 速度限制（详见提案 05/07 节） | 中 | 中（需 TLS1.3+modprobe tls；默认关） |
| ~~O10~~ | ~~Vision-over-TLS（XTLS DIRECT 双向）~~ **（M3 已完成）** | flow=vision 仅限 reality；无内层嗅探/上行 raw | ✅ 实测：tls/reality 内层 TLS1.3 2MB 逐字节 + 双向 DIRECT；ws/wss 逐字节；真订阅 48 节点 5MB e2e（日志 6/6 DIRECT）；见 ADR-0057 | 中 | 低（限 TCP；vision 连接旁路 kTLS） |

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

### O6 · AEAD 方法实测与选择（已完成：结论为保留 chacha）

- **实测（2026-10-05，本机 RustCrypto AEAD，`ss::tests::cipher_microbench`）：**

  | 口径 | aes-256-gcm | chacha20-poly1305 | 说明 |
  |---|---|---|---|
  | AEAD 16KB 块（本项目 `seal()` 口径） | **1.57 GB/s** | **1.73 GB/s** | 含每块 Vec 分配 |
  | AEAD 64KB 块 | 1.59 GB/s | 1.89 GB/s | |
  | GHASH / POLYVAL 单独 | GHASH 2.30 / POLYVAL 2.38 GB/s | — | CLMUL 已启用（cpuid pclmulqdq=true） |
  | 纯 AES 块加密（AES-128 ECB，无 key schedule） | **~6.0 GB/s** | — | AES-NI 已生效（目标文件含 `aesenc`） |
  | 端到端 ss TCP（同二进制，ssserver AES 同方法） | 4.4–8.0 Gbps / CPU 660–720 ms | 5.8–9.7 Gbps / CPU 500–570 ms | 4×48MB，同机轮间噪声 ±30% |

- **结论：不做 AES 优先。** AES-NI 对 AES **块加密**有效（~6 GB/s），但 RustCrypto
  的 GCM 构造受 GHASH（~2.3 GB/s）串行依赖限制，端到端 1.57 GB/s，
  反而不如 chacha（1.73 GB/s）；ss TCP 实测也是 chacha 吞吐更高、CPU 更低。
  M2 文档中「AES-GCM 用户态 6.57 GB/s」更接近 AES 块加密口径（~6.0–6.6 GB/s 实测），
  AEAD 口径下不成立，已在 O6 表中更正。
- **已交付的实现：**
  1. `vmess` 的 `scy=auto/未填` 默认改为 **chacha20-poly1305**（由客户端定，服务端两种都收，互操作不变）；
  2. 组内排序新增 AEAD 方法破紧张：同健康/同延迟时**优先 chacha**（`Outbound::crypto_pref`，
     Min/MinMovingAvg/MinAvg10/Fixed 均适用；Random 保持随机语义）；
  3. `ss::tests::cipher_microbench`（`--ignored` 手动跑）留档，随时可复测。
- **验证：** `SS_METHOD` 参数化后四方对拍可用同一方法复测（`lab/perf/run.sh` 把四份配置
  sed 到 /tmp）；ss TCP A/B 与微基准数据见上表。
- **后续（未做）：** 若要复活 AES 优势，需把 ss/vmess 的 AEAD 换成 **ring/aws-lc** 后端
  （其 AES-GCM 为 AES-NI+PCLMUL 汇编，预期 4–6 GB/s；rustls 已用 ring），属独立优化项。

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

### O10 · Vision-over-TLS：XTLS DIRECT 双向（M3，ADR-0057）

- **实测**：`lab/vision/run.sh`（Xray 25.9.11 服务端 + 内层 TLS 靶站）
  `security=tls|reality`：内层 TLS1.3 **2MB 逐字节一致** + 上行/下行 DIRECT 各触发；
  内层 TLS1.2/明文 HTTP 走 END 互通；`security=ws|wss` 逐字节通过；
  真订阅 48 节点（reality+vision）5MB 下载完整、日志 6/6 双向 DIRECT；`verify` 9/9、`cargo test` 240/240。
- **实现**：① `vision::TlsSniffer`（dae `FilterTLS` 移植：窗口内嗅探内层 ServerHello TLS1.3+cipher）→
  发 `0x02` 双向切裸 TCP（上行 `tls13`/rustls 写半新增 raw 开关）；
  ② rustls 侧不用 unsafe 反射：**逐记录有界读**（恰好整条记录，切换前不多读一字节）；
  ③ vision 连接旁路 kTLS（DIRECT 需中途停用外层加解密）、仅限 TCP；外层非 TLS1.3 显式报错。
- **边界**：依赖对端 Xray 的 DIRECT 语义（非 Xray 服务端按 END 兼容）；
  内层 TLS1.2 不进 DIRECT（嗅探保守，与 Xray 一致）。

### O8 · 缓冲池与回收——✅ 已完成（2026-10-05）

- **交付：**
  1. **`bufpool` 全局缓冲池**：64KB/128KB 两档、**按字节封顶 8MB**，`PoolBuf` Drop 自动归还；
     接入 codec 会话每方向 `out`（最大 churn 点）、回退泵 64KB、UDP 会话槽；
  2. **UDP 会话槽按需增长**：空闲会话只占 1×64KB（旧实现预扩 32 槽 ≈ 2.1MB/会话），
     队列持续深时才逐档扩到上限；
  3. **SIGTERM/SIGINT 优雅退出**：信号→主循环（tick 50ms）→有界等待在途 relay ≤300ms
     →`exit(0)`；数据面钩子是 TCX bpf_link，fd 随进程关闭由内核原子摘除（不残留过滤器黑洞）；
  4. **周期性 `malloc_trim`**（每 30s）：把 glibc arena 空闲页归还内核（churn 后 RSS 回落）。
- **实测（vless-tls，300 条 64KB 短连接 churn）：** RSS 27.3 → 23.9 → trim 后 **23.3 MB**
  （无单调增长；未池化前同口径到 ~40MB 平台）；50 条在途连接下 SIGTERM：整机 **462 ms**
  （内部有界等待 302 ms）、`tc filter` 无残留。
- **期间修复（真实回归）**：ss codec 读半在「帧边界对端正常关闭」时误报 `流在帧中途被截断`
  （数据正确但每连接一条错误日志，并影响 verify 判定）；现干净 EOF 上抛 `Ok(0)`，
  仅半帧 EOF 报错；新增 2 条单测（`classic_clean_eof_at_frame_boundary` / `..._midframe_eof_is_error`）。
- **验证**：`cargo test --release` **257/257**；`test-ss`（无泵失败日志）/`test-vless`/
  `test-ss-udp`/`test-relay-offload`/`test-offload-lifecycle` 均 PASS。
- **已知遗留（与 O8 无关）**：`lab.sh verify` 的 `orig_dst=` 断言在仓库内无任何夹具产生
  （test_proxy/reload/rebind/fault 系列夹具陈旧），已在 backlog G 组登记。

---

## P2 · 线程与规模模型

### O4 · epoll/io_uring worker 池替代「每连接线程」——✅ M4 已完成（stage 1+2 全部交付）

> 2026-10-04 评估结论（用户问询 worker 化/async 的收益）：**worker 化买的是规模与效率，不是峰值吞吐**。
> 依据：relay+splice 已 21.6 Gbps / CPU 仅 150ms（瓶颈是 syscall/内存带宽）；vless 明文 16.2 Gbps / 190ms；
> TLS 受密码引擎限制（内核 2.89 GB/s、用户态 6.57 GB/s）；perf 剖面无单一大锁，线程模型零跨连接共享状态。
> **async（tokio）不加数据面**：沿用 ADR-0003（relay 专用 OS 线程；tokio 仅 QUIC 桥接）。
> **io_uring A/B 已做（2026-10-05，ADR-0058）：收益在噪声内，结论为不引入**（详见下方）。

- **交付（stage 1，2026-10-05，ADR-0058）**：epoll worker 池（核/2，clamp 2–8）接管 **splice 链路**
  （Direct / VLESS 明文 / kTLS 成功的 TLS；每连接 0 线程）；VLESS 响应头由短命 prelude 线程消费后 `resume`；
  非 splice 链路（rustls/reality/ss/vmess）仍走线程模型，stage 2 已全部迁入（见下）。
- **实测（`lab/scale`，direct→epoll 回显，hold 峰值采样）**：

  | 指标 | 线程模型 | reactor |
  |---|---|---|
  | hold 10 000 | 20 011 线程 / 763 MB、建立 5.16 s（1 938/s） | **28 线程 / 32.1 MB**、2.12 s（4 717/s）、fail=0 |
  | hold 5 000 / 1 000 | 10 011 / 2 011 线程 | 28 / 28 线程 |
  | churn 10 s | 20 860 连接/s | **25 606 连接/s**（40 线程） |
  | vless 8×64MB（3 轮均值） | 15.7 Gbps | 16.2 Gbps |
  | vless 64×1MB | 13.2 Gbps | **15.8 Gbps（+19%）** |
  | relay 64×1MB | 13.6 Gbps | **37.9 Gbps** |

  （reactor 为 16 worker 配置——stage 2 起取完整并行度；stage 1 时 8 worker 为 20 线程 / 30.2 MB。）
- **stage 2：codec 会话接入（2026-10-05，ADR-0058 stage 2 节）**：覆盖 **VLESS 全组合**（Tcp/Ws ×
  明文/rustls/REALITY/±vision）、**Trojan**、**vmess**、**ss（classic+SIP022，非 shadow-tls）**、
  **ssr（origin+plain）**、**anytls**（每连接 0 线程；可重入前提：TlsWriter 待刷语义、
  读半状态机（Vless/Vision/Ws/ss/ssr/anytls）、写半待刷队列（Tls13/Vision/Ws/Vmess/ss/ssr/anytls）、
  **预算耗尽自驱补泵**、**vmess 终止帧幂等**）；vless-tls 长连接 2 000 条 = **27 线程 / 61 MB**
  （线程模型 4 011 / 222 MB）、fail=0；vision 夹具 tls/reality/ws/wss 四模式逐字节全过；
  `test-ss`/`test-ss2022`/`test-ssr` 均 PASS 且 `SODAMA_REACTOR_DEBUG=1` 逐连接确认 `codec 投递`；
  anytls 经 sing-box 本地服务端 + 公网目标 e2e HTTP 204、泵失败 0；`SODAMA_REACTOR_CODEC=0` 可关。
- **stage 2 收尾：offload 看门狗单线程统一**：每 offload 连接从 3 线程（monitor+2 驻留泵）降为 **0 线程**——
  hold 200 条 offloaded 连接 28→28 线程、`conns_active=200`，全部回收后 `active=0`/`fast_sock=0`
  （`test-relay-offload` + `test-offload-lifecycle` PASS）。
- **io_uring A/B（结论：不引入）**：微基准 `lab/perf/iou-splice-ab.c`（liburing）交叉配对 10 轮：
  epoll+splice 1 MB 中位 **8.11 GB/s** vs `IORING_OP_SPLICE` **8.18 GB/s**（+0.9%，噪声内）；
  64 KB 管道 io_uring **4.5 GB/s**（更差）；`IORING_OP_SPLICE` 无注册缓冲语义（仅 READ/WRITE_FIXED 有，
  但会引入用户态拷贝）；收益不抵第二套事件后端的复杂度，保留 epoll+splice。

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

- **O7 · UDP（✅ 2026-10-05 完成）**：`recvmmsg/sendmmsg` 批量收发（Plain/Ss；栈上中转、
  `SODAMA_UDP_BATCH=0` A/B）+ 会话表 16 分片（FNV-1a）+ 转发 socket 4–8 MB 缓冲；
  同口径四方对拍工具 `lab/perf/udp.sh`（含限速 `udpblast`）。
  **实测（20k pps、256B、0 丢包）：** sodama CPU 630 ms/40k 包 ≪ dae 2 140 / sing-box 1 580 /
  v2ray 1 780；RSS 28.6 MB 也最小；逐包 ≈15.8 µs（一核 30%）。**批量的边界：** 限速下
  `recvmmsg` 平均每批 ~1 包（strace：recvmmsg 119 728 次 vs sendmmsg 134 次），perf 显示
  63% 在 syscall entry/exit —— UDP 路径不是 syscall 数量问题；顺发/100k pps 下批量小幅领先
  （+0.9%，噪声内），保留但不宣称大幅提升。详细数据与结论见 O7 节。
- **DNS**：命中缓存路径的 syscall 数、并发上限；已独立线程，当前不是瓶颈
  （idle 11 线程、27MB）。
- **半关闭/关闭语义**：splice 链路的 EOF→`SHUT_WR` 已随 O4 stage 1 状态机落地；
  offload 看门狗已随 stage 2 收尾统一为全局单线程（每 offload 连接 0 线程，ADR-0058）。

---

## P5 · 真实节点/公网口径（G1）——✅ 已完成（2026-10-05）

- **夹具**：`lab/perf/real.sh`（client ns — 网关 tproxy — 宿主 — 真实订阅节点 — 公网目标）；
  节点探测工具 `lab/perf/probe-node.sh` / `probe-nodes.py`（凭据只经文件传递、不打印）。
- **对等性**：sodama / dae / sing-box 共用同一节点、同一目标、同一时段；节点域名多 A 记录，
  `prepare` 将后端固定到实测可连 IP（`/tmp/perf-real-node-pinned.url`，0600，不入库）；
  v2ray-core 不支持 VLESS-REALITY，显式 skip。
- **口径**：8 MiB `speed.cloudflare.com/__down`（该端点 bytes≥16 MiB 返回 403+1B，
  夹具用 `curl -f` 且校验 HTTP 200）；节点带宽（≈7–14 Mbps，宿主直连 ≈20.5 Mbps）为共同
  上限，故对比核心指标为**客户端侧 CPU_ms/GB**（进程级、汇总全部线程 `schedstat`，ns 精度）。
- **实测**（17 轮/实现，三轮独立 pass；第三轮固定同一后端）：

  | 实现 | Mbps(med, 17 轮) | CPU_ms/GB(总) | 第三轮（同后端） |
  |---|---|---|---|
  | sodama | 7.3（第三轮 9.7，最高） | **6 233** | **4 987** |
  | dae | 6.7 | 8 820 | 8 613 |
  | sing-box | 7.6 | 8 557 | 10 290 |
  | direct | 20.5 | 0 | — |

  即真实节点口径下 sodama 客户端 CPU/GB 比 dae 低 ≈29%、比 sing-box 低 ≈27%；
  同后端轮 -42% / -52%。
- **踩坑修复**（复用备忘）：direct 轮曾共用并改写 sodama 规则文件→每轮启动重生成；
  TOPO_ONLY 无 direct 通路→基线补 MASQUERADE+FORWARD；官方 dae 重建 dae0→`ensure_dae0`
  自动补建；多后端 IP 不可比→固定后端。

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
sudo REAL_NODE_FILE=/tmp/real-node.url lab/perf/real.sh all  # 真实节点口径（G1，v2ray skip）
sudo lab/perf/run.sh down
perf record -F 1499 -g -p <sodama> -- sleep 12           # 热点搬家（AEAD→? 拷贝→?）
```

目标基线（2026-10-05，M3 后更新）：vless 明文 8 流 **16.2 Gbps / 190 ms**（已达 ≥16 G 目标）、
48MB×4 中位 **16.9 Gbps / 60 ms**；relay 8 流 **21.6 Gbps / 150 ms**；
TLS：kTLS 全链路可用，48MB×4 中位 **12.3 Gbps / 400 ms**，memcpy 1.6%（达标）；
8 流吞吐/CPU 目标（≥13 Gbps/≤1000 ms）因本机夹具（同机 sing-box TLS 服务端 ≈12.5 Gbps 封顶）
与内核密码引擎速度（2.89 GB/s）均不可达——需要“服务端异机”口径后再评（重测项）；
Vision-over-TLS 已交付（双向 DIRECT，ADR-0057）；
M4（2026-10-05 更新）：✅ 线程数 O(核数)——10k 连接 **28 线程 / 32.1 MB**、fail=0；风暴 **25 606/s**；
吞吐不回退（vless 8 流 16.2 vs 15.7 Gbps；64×1 MB +19%；relay +178%）；kTLS 链路逐字节无回归。
stage 2 codec（VLESS 全组合含 reality/vision/ws、Trojan、vmess、ss/ssr/anytls）已全部交付：
vless-tls 2 000 连接 27 线程 / 61 MB（线程模型 4 011 / 222 MB）；
offload 看门狗单线程化后每 offload 连接 0 线程（200 条实测 28→28 线程）；
io_uring A/B 结论为不引入（噪声内，见 O4 节与 ADR-0058）；
ss 8 流 CPU ≤460 ms、四方对比 ss 吞吐目标待 O1/O2/O6 落地后复测。
