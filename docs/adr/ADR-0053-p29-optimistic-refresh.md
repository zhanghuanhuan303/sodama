# ADR-0053：P29 optimistic cache 后台刷新（RFC 8767）

- **状态**：已采纳（2026-10-04）
- **对应**：对标表缺口 #5 DNS 余项中的「optimistic 后台刷新」
- **相关**：ADR-0047（P23 optimistic cache 初版：stale 供应 + TTL 上限）、
  NOTES §11.44；对照 dae `control/dns_control_optimistic.go`
  （`backgroundRefresh` / `refreshDnsRespCache` / `isNegativeResponse`）

## 背景

- P23 实现了 optimistic cache 的「供应」半边：过期条目在窗口内继续应答并把 TTL
  压到 `optimistic_stale_reply_ttl`；但**没有刷新**半边——stale 应答后条目一直旧
  到窗口结束，客户端拿到的也一直是短 TTL 的旧答案。
- dae 的对应实现（RFC 8767 §4）在 stale 命中时置 CAS `refreshing` 并异步
  `backgroundRefresh`：重查上游、成功替换条目、失败保留旧条目；得到负应答时用
  负答案取代被推翻的过期正值；刷新请求保留原查询的 Additional（ECS 等语义）。

## 决策

1. **缓存层（`dns.rs`）**：
   - `DnsCache` 增加 `refreshing: HashSet<String>`（key = 命中的作用域键 +
     qname + qtype + 上游 URL），`begin_refresh`/`end_refresh`/`refreshing_len`
     提供单飞语义（比 dae 每缓存一个 CAS 布尔粒度更细）；
   - 查找新增 `answer_from_cache_ecs_full` 返回 `CacheHit { resp, stale, scope }`
     （stale 标志 + 命中的作用域键，供刷新单飞与负应答取代）；既有
     `answer_from_cache_ecs/scoped` 保持签名不变；
   - `remove_scoped`：按精确作用域键删除（负应答取代正值）。
2. **解析路径（`main.rs`）**：stale 命中 → 先照常回客户端 → 尝试
   `begin_refresh`（失败即合并计数），成功则 `std::thread::spawn` 刷新线程：
   - 用**与触发查询相同的 `query_send`**（含注入的 ECS）重查上游，失败保留旧条目
     并计数；
   - 成功则按 P28 的 ECS 回填逻辑（`ecs_effective_scope`）计算入缓存作用域，
     与主路径一致；
   - 若结果显示为负应答（RFC 2308：NXDOMAIN，或 NOERROR 且 answer 无 qtype/无
     CNAME——`dns::is_negative_response`）且不可入缓存，则删除命中的作用域键
     （取代被推翻的过期正值）；SERVFAIL/超时不取代；
   - 结束时 `end_refresh`（无论成败）。
3. **观测**：状态面 `dns.refresh.{spawned,coalesced,err,inflight}`。

## 理由

- stale 命中路径只多一次 `HashSet::insert` 与一次 `thread::spawn`，不阻塞应答；
  单飞避免 stale 流量向同一上游打重复查询（lab 以「上游增量恰好 1」断言）。
- 负应答取代是 RFC 8767 §4 的明确要求：被权威否定的正值不应在 stale 窗口内继续
  被供应。

## 后果

- 正面：stale 供应的条目会被自动刷新回新鲜值；DNS 域在 dae 语义上补齐最后一项
  （optimistic 两侧对称）。
- 负面/边界：刷新线程与主路径共享全局缓存锁（短临界区）；刷新不做应答路由
  （`dns.routing.response` 的重查/替换）——使用原上游结果，边界记入 NOTES。

## 验证方式

- 单测：`refresh_single_flight`（同 key 合并且结束后可再发起）、
  `negative_response_classification`（NXDOMAIN / 空 NOERROR / 有 A / SERVFAIL）；
  `cargo test --release` **217/217**。
- lab：`test-dns-options` 更新——第二次查询命中 stale（TTL=7）后，假上游在 3s 内
  恰好收到 **1 次**刷新（共 2 次，验证单飞）；状态面
  `dns.refresh.spawned>=1`、`err==0`。
- 回归：`verify` 9/9；`test-dns-cache` 等 DNS 用例。
- 文档：本 ADR + parity v2.6 + HTML v2.37 + NOTES §11.44。
