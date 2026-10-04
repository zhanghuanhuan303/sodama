# ADR-0040：DNS `pname()`（按进程过滤）+ `dns-bench` 并发/多轮 p95

- **状态**：已采纳（2026-10-04）
- **对应**：P18c 实用化扩展（四）：DNS 分流按**发起进程**过滤；上游选型工具量化
- **相关**：ADR-0033（pname/cgroup2 基础）、ADR-0036（`dns.routing`）、
  ADR-0038（sip 请求侧）、ADR-0039（应答侧 sip + bench 初版）、NOTES §11.31；
  dae 对照：其 DNS 路由无 pname 维度；无 bench 并发统计

## 背景

1. 真网关的 `dns.routing` 已能做 `sip()`/`qname()` 分流，但**无法按进程**区分：
   典型诉求是「调试脚本（python3/curl）的 DNS 走直连或拒绝，浏览器不受影响」。
   ADR-0033 的 pname 只服务 TC 分流（WAN egress 新连接反查 `cookie_pid_map`），
   DNS 控制面看不到查询发起者。
2. `dns-bench`（ADR-0039）只有串行 N 次与 p50，评估 DoH 连接复用/排队带来的
   **尾延迟**（p95）与并发行为不足。

## 决策

1. **DNS 侧 pname（mini 扩展）**：
   - **采集**：`split_flow` 在 WAN egress 对 DNS 流（UDP 任意包 / TCP SYN）
     把 `{发起进程名(comm), ktime}` 写入新 map `dns_sender_pname_map`
     （键 = v4-mapped 16B 地址 + **主机序** u16 源端口）。
   - **反查**：DNS 线程用 raw `BPF_MAP_LOOKUP_ELEM`（dup fd，避免持有 `Ebpf`
     借用）；命中且条目 <120s 才生效（端口重用防误判）。
   - **规则**：`dns.routing.request/response` 新增 `pname(...)`（等值、多值 OR、
     支持 `!`；无进程信息不命中，与 TC 侧语义一致）。
   - **回收**：专用线程每 60s 用 raw `BPF_MAP_GET_NEXT_KEY/DELETE_ELEM`
     清理 >120s 陈旧条目（否则客户端源端口轮换会耗尽 4096 槽位）。
2. **bench 并发/多轮**：`dns-bench` 增 `--rounds R --concurrency C`，
   每点总样本 = runs×rounds，`C` 个 scoped 线程并发；输出新增 **p95**。
3. **实现要点（踩坑）**：`MiniTuple.sport` 是**网络序原始值**（u16 从报文
   直接装入），而 map 键统一用主机序——写侧改用 `pkt.h_sport`；首版实测
   「键不匹配、pname 永不错命」，对拍后修正（详见 NOTES §11.31）。

## 与 dae 的差异（如实）

- dae 的 DNS 路由函数没有 pname；本项为 mini 方言扩展。
- dae 无 bench 子命令；并发/多轮/p95 为本工具行为。
- 进程名取 `bpf_get_current_comm`（≤15B），与 ADR-0033 同；非 argv basename。

## 后果

- **正面（实测）**：
  - `cargo test --release` **154/154**（新增 `request_pname_matcher` 等）；
  - 真网关（订阅#2，66 节点组）：临时规则
    `qname(full: example.com) && pname(python3) -> reject` 生效——
    `python3 -c gethostbyname(example.com)` 空应答，`getent hosts` 正常，
    TCP DNS（手写查询）同样命中；移除规则后 reload 恢复；
  - `dns-bench --runs 10 --rounds 2 --concurrency 4`：taobao
    alidns(DoH) p50 9.2/p95 124.8ms、alidns_ecs p50 8.2/p95 109.8ms、
    router(UDP) p50 1.4/p95 24.8ms——清晰暴露 DoH 串行连接在高并发下的尾延迟。
- **负面/代价**：map 条目随 DNS 查询率产生写放大（每查询一次 insert/update）；
  已用 120s 回收兜底。
- **风险**：`dns_sender_pname_map` 满时插入静默失败（反查退化不命中）；
  回收线程 60s 周期内极端端口轮换仍可能短暂触顶（当前实测远未达到）。

## 验证方式（实测）

1. 单测：`cargo test --release`（含 `dnsroute::tests::request_pname_matcher`、
   pname map 结构 `Pod` 尺寸一致性）。
2. lab：`lab.sh dnsroute-up && lab.sh test-dnsroute`（7 请求/5 应答规则矩阵）。
3. 真机：临时 pname 规则 → reload → python3/getent/TCP 三态 → 移除规则回归；
   `dns-bench --rounds 2 --concurrency 4` 记录 p95。

## 修订条件

- 需要按 argv basename 或 cgroup 路径过滤时（对齐 dae 的 argv 优先）；
- map 回收需要更细粒度（如按采样率写入）或改 ringbuf 时；
- bench 需要 UDP/TCP 双协议对比或丢包率统计时。
