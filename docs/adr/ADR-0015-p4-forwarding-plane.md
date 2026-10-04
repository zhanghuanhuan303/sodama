# ADR-0015：P4 范围与边界——TCP relay（dialer）、UDP NAT 会话、TCP offload 最小实现

- **状态**：已采纳（2026-10-03）
- **对应**：ADR-0009 的 P4（转发面）
- **相关**：ADR-0004（Dialer 梯度）、ADR-0008（部署形态）、ADR-0011（过渡一跳 → 由本 ADR 升级为 relay 的一种 dialer）

## 背景

P4 之前，sodama 的「代理出口」只有实验回显与 `--forward socks5://` 一跳：没有真正的转发面，
offload 与 UDP NAT 完全缺失。P4 要补三块：**TCP relay**（真实转发 + 生命周期）、
**UDP NAT**（非 DNS 的代理 UDP）、**TCP offload**（内核内拼接，`fast_sock`/`sk_skb`）。
每块都有必须先定义的语义，否则会把「能跑」做成「跑错」：

1. relay 的上游连接从 host ns 发出，会再次经过自己的 `wan_egress` 钩子 → 必须防自环；
2. UDP NAT 的回包源地址必须是原始目的地址（tproxy 语义），且会话键/超时要与 dae 对齐；
3. offload 的 sockhash 键布局、`__sk_buff` 字段字节序、以及「psock 接管后用户态 read
   的行为」都是实测才会暴露的坑（本 ADR 把它们固定下来）。

## 决策

1. **relay + Dialer（P4a）**：新增 `--dialer direct|socks5://host:port`；`--forward`
   等价于 socks5 dialer（过渡形态，P5 由原生协议栈取代）。accept 仍在 daens，连接经
   mpsc 转交 **host ns 的 relay 线程池**；上游 socket 一律打 `SO_MARK = 0x233`，
   数据面在 `sodama_lan_ingress`/`sodama_wan_egress` 对带 mark 的包直接放行
   （对照 dae `is_dae_socket`）。每连接双向泵送、半关闭（EOF → shutdown write），
   记录 bytes/active，空闲由 janitor（默认 300s，`--relay-idle-timeout`）强制回收。
2. **UDP NAT（P4b）**：透明 UDP 监听按原始目的端口分流：53 → DNS 引擎，其余 → NAT。
   会话键 =（client, orig_dst）；每会话一个 host ns 上游 socket（打 mark，读超时 2s）
   与一个绑定 orig_dst 的透明回包 socket（与 DNS 共用回包 socket 缓存）；上游回包经
   reader 线程直接发给客户端（不绕 dae0）。空闲回收沿用 janitor 线程（默认 60s，
   `--udp-idle-timeout`）。**映射语义按 (client, orig_dst) 分流**：同一客户端去不同
   目的地址用不同上游端口（不是跨目标的 full-cone），回包不校验来源地址。
3. **TCP offload（P4c，最小实现）**：数据面新增 `fast_sock` SOCKHASH 与
   `sk_skb/stream_verdict` 程序 `sodama_tcp_offload`（对照 dae `tcp_offload_redirect`）：
   - 键 =「**对端**收到报文时的四元组」（sip=remote, dip=local, sport=remote_port,
     dport=local_port），因此每个 socket 以 peer 的元组入 map；
   - verdict 按当前 skb 自身元组查到 peer socket 后 `bpf_sk_redirect_hash(..., flags=0)`
     （egress：由 peer socket 发出），未命中返回 SK_PASS（先 lookup 预检再释放引用）；
   - relay 建立后即注册两端（`--offload`，需配 dialer）；注册后用户态泵**继续存在**
     但把 EAGAIN/EOF 当「驻留重试」而不是断连（psock 接管后 read 会 EAGAIN；注册前
     已入队的数据仍需泵排空，顺序天然保持）。
4. **边界（sodama 明确不做，留给后续或不做）**：
   - offload 无 backlog fuse / `tcp_info` 看门狗 / 半关闭计时 / 字节计费 / 暂停与
     用户态回退协调；已 offload 的连接不参与 janitor 回收（进程退出时统一关闭）。
     dae 的对应机制见 `tcp_offload_linux.go`（约 950 行）——sodama 的边界在此，不假装。
   - relay 无嗅探（TLS/QUIC）、无并发上限与 per-conn 超时策略、无 UDP full-cone 跨目标。
   - UDP NAT 不做 DNS 语义特判（DNS 已由独立分支处理）。
5. **验收口径**：
   - `test-relay`：经 relay 访问真实 WAN 目标（8080），512KB 随机数据回显逐字节一致；
     状态面 conns/bytes/dial_errors 正确；
   - `test-relay-idle`：`--relay-idle-timeout 2` 下空闲连接被 janitor 回收（客户端读
     EOF/复位，evicted 计数增长）；
   - `test-udp-relay` / `test-udp-idle`：UDP 经 NAT 到真实目标、3 报文复用 1 会话、
     回包源 = 原始目的地址、空闲会话被回收；
   - `test-relay-offload`：512KB 流经内核拼接（**用户态字节数 0**，verdict/redirect
     计数 > 0）；
   - 回归：原有 9 用例 + DNS/regex 专项 + `forward-up`（现在走 relay+socks5 dialer）
     全部通过，`lab/parity.sh` 逐字节一致。

## 理由

- 「relay 出口从 host ns 发出 + SO_MARK + 数据面跳过」复用 dae 的成熟做法，是避免自环
  的唯一干净路径；实验里用 `rules.udp.dae`（所有 UDP:9998 都判 proxy）正面验证了
  mark 的必要性。
- offload 键布局直接照 dae 推导（peer 元组 + skb 字段），并实测发现两处实现细节
  （`skb->remote_ip4/local_ip4` 是主机字节序、psock 接管后 read 返回 EAGAIN），
  写进 ADR 以免下次重踩。
- UDP NAT 的键与超时按最小可用定义，DNS 继续走自己的分支（缓存/位图不受影响）。

## 后果

- 正面：sodama 具备完整转发面最小闭环（TCP/UDP 真实出口 + 内核拼接 offload），
  `--forward` 升级为 relay 的一种 dialer；状态面新增 `relay`/`udp_nat`/offload 计数，
  转发行为可观测；offload 的「用户态零字节」证据可回归。
- 负面/代价：offload 连接在 sodama 里不回收（长跑场景是 fd/内存泄漏点，进程退出才清）；
  UDP NAT 每目的地址一个上游 socket（端口消耗高于跨目标复用）；relay 线程池每连接
  两线程（无上限）。
- 风险：sockhash 条目无法用 bpftool 枚举（`map dump` 显示 0 条、`map lookup` 返回
  ENOSPC），offload 的观测只能依赖 verdict/redirect 计数与用户态字节数——测试口径
  已按此固定；若内核行为变化导致 verdict 不再运行，`offload_verdicts == 0` 会显式失败。

## 验证方式（实测）

- `cargo test --release`：28/28（转发面无单测，靠 lab e2e）。
- `test-relay`：`stream-ok bytes=524288`；`conns_total=2 bytes_up=524299 bytes_down=524333
  dial_errors=0`。
- `test-relay-idle`：客户端 `after-idle: closed`，`relay evicted>=1`。
- `test-udp-relay`：3/3 应答、`from=2.2.2.2:9998`、`sessions=1/1 errors=0`；
  `test-udp-idle`：`evicted>=1 active=0`。
- `test-relay-offload`：`stream-ok bytes=524288`；
  `offloaded=2 failures=0 userspace_bytes=0 verdicts=42 redirects=42`。
- 回归：标准拓扑 verify 9/9、`forward-up + test-forward`、DNS 五专项 + regex、
  `config-up + test-config + test-status`、`lab/parity.sh` 均通过。

## 修订条件

P5 原生协议栈落地后，dialer 从 `socks5://` 过渡形态切换为协议梯度（ADR-0004），
`--forward` 转为兼容/调试用途；若需要 offload 的 promise（fuse/计费/回收）或 UDP
full-cone 语义，另写 ADR 取代本条第 2/3/4 条对应部分。sockhash 观测受限若被内核修复，
测试可加 `fast_sock` 条目断言。
