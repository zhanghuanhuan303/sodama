# ADR-0052：P28 ECS 回填与 ecs_cache——按上游声明的 scope 作用域化缓存

- **状态**：已采纳（2026-10-04）
- **对应**：对标表缺口 #5 DNS 余项中的「上游 ECS 回填/ecs_cache」
- **相关**：ADR-0038（ECS 注入 `ecs=auto` 与作用域化缓存初版）、NOTES §11.43；
  对照 RFC 7871（EDNS Client Subnet）§7.3（响应中的 SCOPE PREFIX-LENGTH 语义）

## 背景

- P18（ADR-0038）实现了请求侧 ECS 注入：`ecs=auto|<CIDR>` 把客户端子网带给上游，
  缓存键追加 `|ecs=<请求前缀>`；但**应答侧的 ECS 回显被忽略**——
  上游在 OPT 里回传的 SCOPE PREFIX-LENGTH（如 `/0` 表示答案全局有效、`/16` 表示
  整个 /16 可复用、`/32` 表示仅该主机）没有参与缓存语义，导致：
  - 上游声明全局有效的答案无法跨子网共享（每个 /24 各查一次）；
  - 上游声明较宽 scope 的答案同样被按请求 /24 隔离。
- dae 主线不做 ECS（`ecs=`/`sip()` 均为 mini 扩展），此项为 mini 方言的能力补齐。

## 决策

1. **应答侧 ECS 解析**（`dns::parse_ecs_echo`）：从应答的 OPT RR（`parse_rrs` 复用）
   解出 ECS option 8 的 `FAMILY / SOURCE-PREFIX / SCOPE-PREFIX / ADDRESS`；非法/越界
   返回 `None`（回退既有行为，不报错）。
2. **回填入缓存键**（`main.rs` 解析路径）：注入 ECS 的查询得到应答后——
   - 应答带 ECS 回显：以 `|ecs=<truncate(回显地址, scope)>/<scope>` 入缓存
     （scope=0 → `0.0.0.0/0`、`::/0` 全局键）；
   - 无回显：回退请求前缀（P18 行为不变）；
   - 状态面：`dns.ecs.echo`（回填次数）与 `dns.ecs.scope`（最近一次回填值）。
3. **ecs_cache 阶梯查找**（`dns::ecs_scope_ladder` + `DnsCache::answer_from_cache_ecs`）：
   命中尝试从请求前缀开始：请求前缀（等值，如 /24）→ **客户端完整地址的主机前缀**
   （/32、/128；上游回填 scope=/32 时同一客户端可命中）→ 更粗的规范前缀
   （v4：/20 /16 /12 /8 /0；v6：/48 /32 /0），命中上游回填的更宽 scope。
   方向性保证：只会「向宽」复用（客户端前缀 ⊆ 条目 scope），绝不把窄答案给宽网段；
   多候选全 miss 只计一次 cache miss。
4. **注入前缀语义修正**：`ecs=auto` 现在把**客户端完整地址**传给 `add_ecs`
   （由它按前缀截断写入线上），阶梯据此才能构造精确的 /32 主机候选；此前
   `ecs_auto_prefix` 先把地址截断到 /24，会让 /32 回填键错误地覆盖整个 /24。
5. **显式边界**：不做乐观预取/后台刷新（stale 语义仍由 optimistic cache 承担）；
   不做上游 ECS 剥离（客户端自带 OPT 仍透传、不入缓存，既有语义）。

## 理由

- RFC 7871 的 scope 语义就是「答案可复用的最宽网段」，把它作为缓存键即可同时
  获得正确性与共享率，无需引入额外索引结构（阶梯是少量哈希查找）。
- 阶梯只尝试规范前缀（/24、/20、/16…），覆盖上游常见回显（0、与源同前缀、/16、/32）；
  非规范 scope（如 /22）不在阶梯中，按 miss 处理（保守正确）。

## 后果

- 正面：ECS 上游的答案按声明 scope 复用（全局/宽 scope 一份答案服务多子网），
  上游查询数与缓存条目数下降；观测可直接用状态面两个字段断言。
- 负面/边界：如上第 5 条；回显 scope 越宽则答案越「粗糙」（这是上游自己的声明）。

## 验证方式

- 单测（`dns.rs`）：`parse_ecs_echo`（v4 scope=0/16、无 OPT、非法输入）、
  `ecs_scope_ladder`（v4/v6 顺序与截断）、缓存集成三例——/16 跨 /24 命中且不同
  /16 不命中、/0 全局命中、/32 仅本机命中（别的客户端不命中）、客户端自带
  OPT 不入缓存；`cargo test --release` **215/215**。
- lab（`lab/ecscache.dae` + fake_dns 的 `ECS_ECHO` 表）：
  `ecscache-up` + `test-ecs-cache`——`ecs0.test`（scope=0）两次查询上游只收到 1 次；
  `ecs16.test`（scope=/16）两次查询上游只收到 1 次（第二次走回填键）；
  状态面 `dns.ecs.echo>=2`、`dns.ecs.scope=="10.0.0.0/16"`。
- 回归：`verify` 9/9；`test-dns-cache` / `test-dns-options` / `test-dnsroute`（ECS
  注入路由）全 PASS；真机重启自检 + 66/66 + 0 panic。
- 文档：本 ADR + parity v2.5 + HTML v2.36 + NOTES §11.43。
