# ADR-0022：P7 收敛——剖面口径、offload 生命周期修复、soak 与静态发布

- **状态**：已采纳（2026-10-04）
- **对应**：路线图 P7（性能剖面 → 优化 → soak → 发布工程）
- **相关**：ADR-0015（relay/offload）、ADR-0020（QUIC 会话边界）、ADR-0009（内核先行）、ADR-0021（运维面）

## 背景

P7 要做的是收敛：先量化，再按数字优化，然后长稳与发布。三个现实约束：

1. **perf 不可用**：`perf_event_paranoid=2` 且机器上没有 `perf` 二进制，也没有安装条件
   （网络受限）。因此本阶段的剖面口径只能是「墙钟吞吐 + 状态面 counters + `/proc` CPU/RSS」，
   **没有采样热点**；这一点必须在所有结论里如实标注。
2. Python 探针（`client_probe.py`/`stream_probe.py`/`wan_echo.py`）作为端点会先于 sodama
   成为瓶颈，无法比较路径吞吐。
3. P4c 的 offload 是最小实现，对照 dae `control/tcp_offload_linux.go` 缺了会话层：
   注册前队列检查、半关闭/终止判定、fast_sock 键注销。C 基准一压就暴露（见下）。

## 决策

### 1. 剖面工具与口径（`lab/bench_io.c` + `lab/bench.sh`）

- C 端点：TCP/UDP echo 服务端 + 多流客户端（带模式校验）、ping-pong RTT（p50/p99）；
  gcc 编译到 `build/bench_io`；服务端在 wan ns 内替换 Python `wan_echo`（bench.sh 负责换）。
- 路径：`direct`（内核直转基线）/`relay`/`offload`/`ss`/`udp-direct`/`udp-nat`；
  每条路径 CPU=进程 `utime+stime` 增量、RSS=`VmRSS`、字节=状态面 `sodama_relay_*`/`udp_nat_*` 增量。
- 客户端「收满即停」：吞吐只计数据面，不等 EOF；半关闭语义由专项用例覆盖。
- 为 direct 路径新增 `bench-up` 会话（`lab/rules.bench.dae`：10.9.9.0/24 全直连）。

**P7 基线数字**（本机 16 核 / veth 拓扑 / 单次取数，量级对齐即可）：

| 路径 | 吞吐 | RTT p50/p99 | userspace CPU | 备注 |
|---|---|---|---|---|
| direct | 31.1 Gbps | 10 / 25 µs | 0 | 内核转发基线 |
| relay | 24.7 Gbps | 17 / 142 µs | 447 ms/GB | 用户态泵（64KB 缓冲） |
| offload | 14.6 Gbps | 23 / 107 µs | ≈0（1.8MB/GB 量级的注册前残余） | 内核对拼；吞吐低于 relay，未深究（如实记录） |
| ss | 2.5 Gbps | 55 / 213 µs | 1267 ms/GB | chacha20-poly1305 单线程/连接 |
| udp-direct | — | 8 / 22 µs | 0 | 逐包 echo |
| udp-nat | — | 15 / 68 µs | ~50µs/包对 | 会话表 + transparent 回包 socket |

UDP blast 模式在本环境被端点/回环丢包主导（loss ~56%），不作为吞吐口径，仅作相对参考。

### 2. offload 生命周期修复（核心正确性）

基准压测暴露的问题（逐一有最小复现与修复）：

1. **不用用户态传播 FIN**：RDHUP 时仍有排队数据在重定向路径上，`shutdown(SHUT_WR)` 会截断
   （实测 32MB 流只剩 0.3–17MB）。改为 dae 会话层语义：**两侧 RDHUP → 干净退出；
   单侧 RDHUP 超过 10s（对照 dae `relayHalfCloseTimeout`）→ 强制关闭两侧**。
2. **不特殊处理 0 长度 skb**：给 `sk_skb/stream_verdict` 加 `skb->len==0 → SK_PASS`
   反而会让 psock 吃掉 EOF 并停滞在途数据（实测 10s 只走 MB 级）。保持与 dae 相同，
   FIN 交给 sk_skb 路径。
3. **POLLERR 是常态不是终态**：FIN 重定向尝试会在源 socket 留下 `POLLERR`；在传输中按它
   force-close 会切断全部在途数据。看门狗只把「无 RDHUP 的 ERR/HUP」当错误。
4. **fast_sock 键必须注销**：sockmap 条目持有 socket 引用，不删则 fd 与内核态 socket 泄漏
   （soak 会直接涨 fd）。连接终结（看门狗置 stop → 泵退出）后删除两个键。
5. **注册前 drain 接收队列**：队列里已有数据会被用户态泵与内核重定向**双路径**处理
   （实测 8MB 多出 17B；后确认为 Python 前缀干扰，但 dae 的
   `tcpConnHasPendingReadData` 拒绝逻辑仍是正确性护栏），对齐实现：排空 + 出错拒绝注册。

**明确不做**：backlog fuse（pause map）、`skb_send_sock` kprobe 精确计费、tcp_info 看门狗——
sodama 用「半关闭超时 + 看门狗回收」兜底；代价是只做半关闭、不做反向关闭的协议最多等 10s
（dae 同样有 10s 上限）。

### 3. 优化（先测后改，逐条留数字）

- **TCP_NODELAY**：控制面出站 socket（`outbound::marked_tcp_connect`）与 tproxy accept
  的连接全部关 Nagle。ss 路径 ping-pong p50 从 **43.3ms → 55µs**（帧头+载荷多次小写触发
  Nagle 等 ACK）；relay 保持 ~17µs。
- **bench 工具**：`metric()` 必须先完整读取 metrics 再过滤，避免 `awk exit` 提前关管道
  导致客户端 EPIPE panic（pitfall #10 的变体）。
- 未做：relay 泵缓冲调参（24.7Gbps/447ms per GB 已在可接受区间）、UDP 会话表分片
  （RTT 15µs、无锁竞争证据）、offload 吞吐追因（记录差异，不猜结论）。

### 4. soak（`lab/soak.sh`）

循环：bench_io 打流（tcp/ss 4MB×2 流；udp 500×256B）→ 每 2 轮 reload → 每 3 轮
suspend + 挂起期直连校验 + resume。结束静默 12s（idle 2s + janitor 5s + 看门狗余量）后断言：
连接/映射/session 归零、RSS 与 fd 增长受限、零失败轮。默认 60s（CI 友好），可传秒数。

**实测**（本机）：

- tcp 60s：870 轮，435 次 reload、290 次 suspend/resume，RSS +368kB、fd +0；
- ss 30s：342 轮，RSS +440kB、fd +0；
- udp 30s：1382 轮，fd 回基线；RSS +30.9MB 是 **glibc 多线程 arena 保留**而非逻辑泄漏
  （`MALLOC_ARENA_MAX=1` 下 60s 仅 +7.9MB；fd 无增长、增量不随轮数线性增长），
  脚本对 udp 模式放宽到 48MB 并注释原因。

### 5. 发布工程（`lab/build-static.sh`）

- **路线**：glibc 全静态 `-C target-feature=+crt-static`（static-pie），产物不依赖动态
  加载器；`redis:7-alpine` 冒烟通过（`validate` 6 可编译/1 deferred、`export-config`）。
- **musl target 暂不可用**：rustls(ring) 交叉需要 `x86_64-linux-musl-gcc`（本机无）；
  本轮把源码里两处 libc 跨实现类型差异修好（`main.rs` 的 `SIOCGIFHWADDR` ioctl 签名、
  `msg_controllen` 在 glibc/musl 的类型差，均改 `as _`），装上 musl 工具链即可直构
  （**本机未验证**）。
- 已知边界：glibc 静态二进制不适用依赖 NSS 的域名解析与 dlopen；eBPF 加载仍要求在宿主
  netns/特权环境（alpine 冒烟只覆盖用户态路径）。

## 理由

- 没有 perf 就不做重 CPU 优化（relay/offload 已到 20+Gbps 量级，瓶颈在端点/拓扑而非
  用户态拷贝）；把精力放在 soak 暴露的正确性问题上；
- offload 生命周期对齐 dae 的**语义**（半关闭超时、队列检查、键注销）而不是实现
  （fuse/kprobe），最小增量获得正确性；所有取舍都可用 `test-offload-lifecycle` 与
  soak 复现；
- 发布路线选 crt-static 是「当下环境可验证」的静态方案；musl 的阻塞点是工具链而非代码，
  把代码差异修掉、把命令写进脚本，环境具备时一条命令切换。

## 后果

- 正面：offload 连接可回收（`conns_active`/`fast_sock` 归零），fd/RSS 不再随连接数泄漏；
  ss 等协议栈小包延迟从 40ms 级降到微秒级；有可复现的剖面/soak/静态构建工具链；
  回归多了一条 `test-offload-lifecycle`。
- 负面/代价：只做半关闭的协议在 offload 下最多等 10s（与 dae 相同）；udp soak 的 RSS
  阈值因 glibc arena 放宽（写清原因，不作为泄漏指标）；静态发布暂用 glibc static-pie
  （NSS 限制）。
- 风险：offload 吞吐低于 relay 的成因未定（记录在案，不影响正确性）；`verify` 用例
  （尤其 rebind）对时序敏感，**不要在并行负载下跑**（本轮出现过一次抖动，复跑通过）。

## 验证方式（实测）

- `cargo test --release` 73/73；标准/单臂 verify 9/9；DNS 六专项；relay/offload/UDP
  六专项（含新增 `test-offload-lifecycle`：半关闭超时后 `active=0`、`fast_sock=0`）；
  G1/G2/G3a/G3b 全套（ss/trojan/vless/vmess/tuic/hy2 × TCP/UDP/TLS/obfs/brutal/hop）；
  `test-ops`、`test-config-reload`；`lab/parity.sh` 逐字节一致；`lab/proto-check` vless/vmess；
- `lab/bench.sh all`（六路径表）；`lab/soak.sh run <30|60> <tcp|ss|udp>` 三模式通过；
- `lab/build-static.sh`（+`SMOKE_ALPINE=1`）。

## 修订条件

若拿到 perf 或 eBPF 采样能力，另写 ADR 取代「无热点剖面」口径并补 CPU 侧结论；
若引入 dae 的 backlog fuse/tcp_info 计费，或换成 musl 发布路线，同样新写一条互链
（本条的对应子条被取代即可）。
