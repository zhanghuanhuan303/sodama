# ADR-0039：应答侧 `sip()` + `dns-bench` 上游 A/B 对比工具

- **状态**：已采纳（2026-10-04）
- **对应**：P18c 实用化扩展（三）：响应侧按客户端过滤、上游选型量化
- **相关**：ADR-0036（`dns.routing`）、ADR-0038（ECS/sip 请求侧）、NOTES §11.30；
  dae 对照：其 DNS 应答路由函数仅 qname/qtype/upstream/ip，无 `sip`；
  上游无内置 bench 子命令

## 背景

- 请求侧 `sip()` 落地后（ADR-0038），响应侧仍无法按来源区分策略：
  例如「内网客户端才拒绝某类应答」「访客网段强制换上游」。
- 真网关把国内域从 `router` 切到 `alidns_ecs`（DoH+ECS）后，只有命中计数
  （`upstream_hits`）说明路径，缺少**同域名跨上游的延迟/答案对比**工具，
  选型只能靠体感。

## 决策

1. **应答侧 `sip(...)`**（`dnsroute.rs`，mini 扩展）：
   - 与请求侧同义：CIDR/`geoip:`/`ext:`，支持 `!`，与 qname/qtype/upstream/ip
     同链参与 `&&`/fallback；
   - `response_select_for(resp, served, client)`：客户端地址由 main 透传
     （UDP 取 recvmsg 源地址、TCP 取 `peer_addr()`）；无来源信息时不命中；
   - 兼容签名 `response_select(resp, served)`（= client None）保留给测试。
2. **`dns-bench` 子命令**（mini 扩展工具；用户态、不加载 eBPF）：
   - `mini-dae dns-bench --config <file.dae> --names a,b [--tags t1,t2]
     [--runs N] [--client <IP>]`；
   - 从配置构建与运行时同一套 `UpstreamSet`（`build_upstream_set_core` 复用），
     对 names × tags 逐条 `exchange()`，输出 ok 数、min/avg/p50（ms）、
     ancount、首条 A/AAAA TTL；
   - `--client` 供 `ecs=auto` 注入子网（缺省不注入）；
   - 上游 socket 走 marked 路径（`SO_MARK`），**运行中的网关不会二次接管
     探测流量**（需 root；工具文档已注明）；
   - 结果仅供选型参考：无本地缓存、每次真实往返，TTL 来自上游。
3. **测试**：`response_sip_filters_by_client` 单测（命中/跳过/无来源三态）；
   lab `dnsroute.dae` 增两条应答规则（不同网段互斥）+ `test-dnsroute` 断言。

## 理由

- 答复侧 `sip` 与请求侧共用 `ip_set`/`ip_hits`/链编码，改动面极小的同时
  解锁「按来源过滤应答/审计」的常见需求（如仅对访客网段做拦截）。
- `dns-bench` 复用生产代码路径（同一 `Upstream` 实现、同一解析/ECS 逻辑），
  测的就是线上行为；marked socket 保证与透明代理共存。

## 与 dae 的差异（如实）

- dae 无应答侧 `sip`、无 bench 子命令；两者均为 mini 方言/工具扩展。
- bench 的 p50 是 N 次样本中位数（默认 5），不追求统计严谨；不测并发。

## 后果

- **正面（实测）**：
  - `cargo test --release` **146/146**（新增应答侧 sip 单测）；
  - lab `test-dnsroute`：7 请求/5 应答规则矩阵全过（客户端 10.0.0.2 命中
    `sip(10.0.0.0/24) && ip(...) -> reject`，先序的 10.9.9.0/24 规则正确跳过）；
  - 真机 bench（订阅#2 网关运行中，client=192.0.2.254，runs=5）：
    `www.taobao.com`：router 1.31ms / alidns(DoH) 7.43ms / alidns_ecs(DoH+ECS) 7.45ms；
    `www.baidu.com`：1.32 / 7.37 / 7.24；`www.google.com`：1.32 / 7.25 / 6.81（p50）；
    三者均 5/5 成功；ECS 与普通 DoH 的应答 TTL 不同（15 vs 60 等），
    说明上游视角确实按子网变化。
- **负面/代价**：bench 串行为主（N 小）；TLS 上游首次含握手（后续持久连接，
  符合线上复用行为）。
- **风险**：公共上游可能对同域名轮流返回不同 CDN 节点，样本小则噪声大
  （p50 + min 一起看；必要时加 `--runs`）。

## 验证方式（实测）

1. 单测：`cargo test --release`（`response_sip_filters_by_client`）。
2. lab：`sudo lab/lab.sh dnsroute-up && sudo lab/lab.sh test-dnsroute`。
3. 真机：`sudo ./target/release/mini-dae dns-bench --config lab/gateway.dae
   --names … --tags router,alidns_ecs,alidns --runs 5 --client <本机 IP>`。

## 修订条件

- 需要并发/多轮统计（p95、丢包率）或从状态面实例内发起 bench 时；
- 应答侧需要更多来源维度（如 pname/接口）时；
- bench 需要 UDP/TCP/EDNS 变体（当前固定 A/IN、无 EDNS）时。
