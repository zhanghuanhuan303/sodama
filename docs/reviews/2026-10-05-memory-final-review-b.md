# 第三方书面评估（B）——内存终测报告

> 存档说明：以下为第三方书面评估原文（用户转贴），仅做排版整理；观点不代表本项目立场。
> 评审对象：`docs/memory-report.html` v1.0（五方内存终测，2026-10-05）。工程方回应见 `2026-10-05-adoption-proposal.md`。

我看懂了。先不纠结乱码，这份报告本质上是在评审你这个 Sodama 网络代理/数据面轮子的内存与高并发设计。

我的判断是：报告抓到了一个非常关键的问题，但其中有几处技术结论说得过头了。
如果这是你自己造的轮子，我反而认为现在最值得做的不是继续优化 RSS，而是把
「用户态内存优势 → 系统总内存优势」这条证据链补完整。

## 1. 最有价值的结论，其实不是 12.5 MB

你现在最漂亮的数据是：

```
20,012 threads / 527.4 MB
        →
Reactor 29 threads / 34.8 MB
```

这说明你的 Reactor 架构确实解决了一个很典型的问题：**connection ≠ thread**。

如果这些连接原来是一连接一线程，那么线程栈、TLS/上下文、调度器对象以及大量 per-connection state
都会随着并发线性增长。而你现在：

```
20,012 connections
        │
        ▼
   Reactor workers
        │
   ┌────┼────┐
   ▼    ▼    ▼
event event event
```

这才是 Sodama 真正值得强调的架构成果。

但是报告里有一句：「完美证明了基于事件驱动的 Reactor 池是高并发网络 I/O 的唯一解」——这个结论不成立。
Reactor 是一个很成熟、优秀的解法，但不是「唯一解」。例如 io_uring、异步 runtime、thread-per-core、
M:N scheduling 等也可以达到类似目标。所以如果这是准备作为正式 benchmark/report，我会把它改成：
**证明 Sodama 当前 Reactor 架构能够以极低的线程和用户态内存开销承载高并发连接。** 这就非常硬。

## 2. 报告真正抓到的 bug：Pipe

这一部分我基本赞同，而且我认为它比报告作者自己意识到的还重要。

你现在如果：

```
client fd → pipe → pipe → upstream fd
```

然后每条连接创建 pipe pair，那么 2000 connections × 多个 pipe fd，很容易出现一个非常奇怪的现象：
**用户态 RSS 看起来漂亮得离谱，但整个机器的内存并没有那么漂亮。**

这是做网络代理非常容易掉进去的坑。因为你现在优化的是 Process Memory，但真正应该看的其实是 System Memory：

```
System Memory
├── userspace RSS
├── kernel slab
├── socket buffers
├── pipe buffers
├── conntrack
├── eBPF maps
├── skb
└── other kernel objects
```

所以下一版 benchmark 最好不要再只测 `/proc/$PID/status`，而应该增加：

```
/proc/meminfo
/proc/slabinfo
/proc/$PID/fd
/proc/$PID/status
/proc/$PID/smaps_rollup
```

如果是 Linux 网络程序，我甚至建议直接加：

```
slabtop
ss -m
cat /proc/net/sockstat
cat /proc/net/sockstat6
```

这样你就能回答一个非常重要的问题：**Sodama 到底是真的省内存，还是只是把内存从 userspace 搬到了 kernel space？**
这才是专业 benchmark。

## 3. 但报告对 Pipe 的一个地方需要纠正

报告说「Linux 每个 pipe 默认分配 16 页，也就是 64 KB」——这个说法不能直接当成普遍成立的硬规则。
Linux pipe buffer 的实际行为和 kernel version、pipe capacity、用户权限、pipe 使用方式、
buffer 是否实际占用、内核的 pipe page accounting 都有关系。尤其是：**pipe capacity ≠ 实际 resident
memory 一定就是 capacity**。所以 `2000 × 2 pipes × 64 KB ≈ 256 MB` 这种算法可以作为最坏情况下的
粗略上界估计，但不能直接说「你的系统已经吃掉了 256 MB kernel memory」。这需要实测。
这一点我建议你反而自己做实验，把报告中的推测变成数据。

## 4. 真正值得你做的实验

我建议直接做一个 **Sodama Kernel Memory Benchmark**，测试 connections：100 / 500 / 1,000 / 2,000 /
5,000 / 10,000 / 20,000。每个点记录：

- **Userspace**：VmRSS、VmSize、Threads、FDs、Heap、malloc arena
- **Kernel**：Slab、SReclaimable、SUnreclaim、Sock、Pipe、skb
- **Network**：TCP memory、socket buffers、conntrack
- **eBPF**：map memory、program count、ring buffer、per-cpu allocations

最后得到：

```
              Sodama
                │
    ┌───────────┴───────────┐
    │                       │
Userspace                 Kernel
    │                       │
   RSS                    Slab
  Heap                   Socket
Threads                   Pipe
   FD                      skb
    │                       │
    └───────────┬───────────┘
                ▼
           TOTAL MEMORY
```

这张图出来以后，你这个项目的技术说服力会比现在高一个档次。

## 5. Pipe Pool 是值得做，但我不会马上做

方向是对的，但是我不会简单地实现 connection → borrow pipe → splice → return pipe，因为这里有一个
非常值得你重新思考的问题：**你真的需要 pipe 吗？** 如果 Sodama 的核心已经是 eBPF + Reactor + zero-copy，
那么 Pipe 很可能只是历史实现路径。你真正应该 benchmark：

- 方案 A：`socket → pipe → socket`（splice）
- 方案 B：`socket → socket`（send/recv）
- 方案 C：io_uring
- 方案 D：sendfile / MSG_ZEROCOPY / 其他 zero-copy path

看看在你的实际代理 workload 下：CPU、latency、throughput、RSS、kernel memory、syscalls、connections/sec
究竟谁最优。如果 Pipe 只是为了获得 splice 的 zero-copy，那么它本身很可能已经成为你的**架构税**。

## 6. FD 数量问题尤其值得重视

报告说 8 FD / connection。如果真实如此，那么 2,000 connections → 16,000 FD，这确实是一个很大的
architectural smell。因为 Reactor 的核心优势本来应该是：大量 connection + 少量 execution context。
但如果为了实现 forwarding：1 connection → 8 fd，你实际上又把资源膨胀转移到了 FD 层。

理想状态应该尽量接近：

```
connection
    │
    ├── client socket
    └── upstream socket
```

也就是 **2 FD / connection**。然后 10,000 connections → 20,000 FD，这个规模就舒服很多。

## 7. 你的下一阶段优化顺序，我会和报告略微不同

- **P0 — 先证明 Kernel Memory**。不是马上优化，先测：RSS + Slab + Socket memory + Pipe memory +
  eBPF memory = Total。否则你不知道问题到底在哪里。
- **P1 — 搞清楚为什么一条连接需要 8 FD**。这个我认为比 Pipe Pool 更重要。做一张 Connection FD Topology，
  明确 FD 0…FD 7 每个 FD 为什么存在。然后问：能不能压到 2？如果能，这可能是 Sodama 下一版最大的架构收益。
- **P2 — Pipe Pool**。如果确认 splice 仍然是最佳 forwarding primitive，再做 pool。而且最好不是简单的全局 pool，
  而是 Reactor Worker → local pipe cache，避免 worker → global pipe pool → lock contention。
- **P3 — 72h Soak**。尤其你现在已经有 26k conn/s 这种 churn benchmark，那么非常适合做 24h / 48h / 72h，
  观察 RSS、FD、Slab、socket memory、CPU、latency、connection failure，最重要的是画成曲线。
  如果 72 小时之后 RSS ≈ constant、FD ≈ constant、Slab ≈ constant，那你就真的可以开始说
  **bounded-memory architecture**——这个词比「内存很小」有价值得多。

## 8. 技术定位

如果 benchmark 数据是真的，而且不是人为针对 Sodama 调参，那么你的项目已经不只是「又写了一个代理」，
而开始变成：**极低资源占用的 Linux userspace networking dataplane**。特别是
eBPF + Reactor + zero-copy + bounded allocation + aggressive memory reclamation 这个组合是有技术辨识度的。

甚至可以形成一个非常漂亮的设计目标：

```
                  SODAMA
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
      CPU          RAM          FD
       │            │            │
    Reactor      bounded       2/socket
                 memory
        │            │            │
        └────────────┼────────────┘
                     ▼
              predictable
             high concurrency
```

「Predictable resource consumption」可能比单纯的 benchmark 峰值更值得你追。

## 最后一个很重要的判断

这份报告有点「看到漂亮数字以后兴奋过头」。比如：15 倍内存收益、690 倍线程开销减少、唯一解、顶级性能、
遥遥领先——这些作为项目内部庆祝没问题，但作为正式技术报告，我会全部降调。因为真正懂 Linux networking
的人下一句话一定会问：「**RSS 很低，那 kernel memory 呢？**」而这恰恰是报告已经帮你找出来的突破口。

所以我建议你不要急着做更多 userspace micro-optimization。下一版直接把 benchmark 升级成：
Process Memory → Kernel Memory → Total System Memory → Resource/Connection 四层模型。
如果 Sodama 在 20k/50k/100k connection 下，依然能证明总内存近似有界、FD 可控、kernel slab 不泄漏，
那这个轮子的技术含金量就明显不是「造了个能用的代理」了，而是开始有资格拿去和 dae / sing-box / mihomo
这种成熟 dataplane 做非常严肃的工程横评。
