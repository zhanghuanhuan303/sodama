# ADR-0036：P18c `dns.routing` 请求/应答分流 + 多上游

- **状态**：已采纳（2026-10-04）
- **对应**：P18 缺口 #5 之 **c 段**（收尾）
- **相关**：ADR-0034/0035（P18a DoT/DoH、P18b DoQ）、ADR-0012/0013/0014（明文 DNS/缓存）、
  NOTES §11.27；上游对照 `component/dns/request_routing.go`、`response_routing.go`、
  `function_parser.go`、`control/dns_controller_handle.go`（`RequestSelect`/
  `ResponseSelect`/`resolveDNSUpstream`）

## 背景

- dae 的 `dns.routing`（研究结论）：
  - `request` 函数 `qname`（suffix/full/keyword/regex/geosite/ext；裸值默认 suffix）与
    `qtype`（类型名/数字）；出口 `reject`（**空应答 NOERROR**）、`asis`（发往客户端
    原始目的地址，**总是 UDP**）、或 `dns.upstream` 的 tag；默认 fallback `asis`；
  - `response` 函数 `qname`/`qtype`/`upstream`/`ip`（裸 CIDR/geoip/ext）；出口
    `accept`、`reject`（**保留 rcode/其它段，仅清空 answer**，且**入缓存**）、或 tag
    （**换上游重查**，`MaxDnsLookupDepth=3`，即最多 2 次重查）；默认 fallback `accept`；
  - 请求路由**先于缓存**（reject 规则不被缓存旁路）；缓存键含 upstream（`responseCacheKey`）；
  - 规则链编码（Match 算法）：同一行 `&&` 的每个函数末尾标 `And`（LogicalAnd）、
    多值函数中间项标 `Or`、整行末尾为真实出口；`!` 作用于整个函数；
  - `sub/node/subnode` 只匹配 dae 自身订阅/节点查询，普通查询永远不命中。

## 决策

1. **新模块 `loader/src/dnsroute.rs`**：把 config AST 编译为
   `DnsRouter{ req/resp 条目, DomainSetSpec 集合, ip 前缀集, 出口, fallback, notes }`；
   匹配循环逐行复刻 dae 的 `goodSubrule/badRule` 链编码；domain 复用
   `rules::DomainSetSpec`（suffix/full/keyword/regex + 前导点/大小写语义一致）；
   `qtype` 内置常用类型名表（A/NS/CNAME/SOA/PTR/MX/TXT/AAAA/SRV/NAPTR/CERT/DNAME/
   OPT/DS/SSHFP/RRSIG/NSEC/DNSKEY/NSEC3/TLSA/SVCB/HTTPS/CAA + 数字回退）。
2. **多上游**：`main.rs` 的 `UpstreamSet{ by_tag, legacy, asis 缓存 }`；
   CLI `--dns-upstream` → 单 tag `default`（覆盖一切）；否则 `dns.upstream` map
   （dae 同构，tag 引用在编译期校验，未知 tag 硬失败）。
3. **请求流程**（`resolve_dns`）：请求路由 →（reject：空应答立即返回，**不缓存**）→
   按**作用域**查缓存（`tag|<tag>|<url>` / `asis|<addr>` / `legacy|<url>`）→ 上游 →
   **应答路由循环**（`Accept` 结束 / `Reject` → `dns::strip_answers` 后**入缓存** /
   tag → 换上游重查，深度上限 3）→ 发布域位图 → 回填缓存。
4. **`asis`**：UDP 路径用 `recvmsg` 的 `IP_ORIGDSTADDR`；TCP 路径用透明套接字的
   `local_addr()`（tproxy 保真）；按地址缓存 `udp://` 上游对象；拿不到原目的时
   （异常路径）退回 legacy 并计数。
5. **兼容**：仅当配置存在 `dns.routing` 段才启用路由（fallback 缺省 asis/accept）；
   无该段时保留 legacy 单上游行为（不改变既有网关/实验语义）。
6. **lab**：`lab/dnsroute.dae`（两假上游 up1/up2 + 4 条请求/3 条应答规则）+
   `fake_dns.py` 支持 bind 地址与第二实例 + `dnsroute-up`/`test-dnsroute`
   （reject 不上行、qtype reject、suffix→up2、缓存作用域、fallback、应答 reject
   清空 answer、应答重查到 up2、UDP/TCP asis 回原目的、dns.routing 热重载）。

## 理由

- 语义按 dae 逐步对齐（含链编码与默认 fallback），使真实 `dns.routing` 配置可直接迁移；
- `asis` 真正回原目的地址（而不是固定上游）是 dae 的关键行为，透明 DNS 场景下
  等价于「照常问用户本来就配置的 DNS」；两种客户端路径都能拿到原目的，故完整实现；
- 路由先于缓存 + 作用域化缓存键，避免「换了上游还吃旧答案」这类静默错误。

## 与 dae 的差异（如实）

- **无 `sub/node/subnode`**：mini 没有「daemon 自身订阅/节点域名查询」这条内部路径；
  含这些函数的规则被跳过并记 note（dae 中它们对普通客户端查询同样不命中，效果等价）。
- **`upstream(...)` 按名字比较**：dae 用数值 index（`Reject`/`AsIs` 的常量值与
  response 出口常量复用，导致 `upstream(reject)` 数值上等价于命中 asis）；mini 不
  复刻这种数值巧合，`upstream(asis)`/`upstream(reject)`/`upstream(tag)` 语义直白。
- **`ip(geoip:…)` 运行时线性前缀匹配**：应答 IP 数少（个位数），每应答 × 前缀数
  的按位比较；dae 用 128 位 trie。语义一致，规模敏感度不同。
- **无该段时的默认**：dae 默认 `asis`；mini 保留 legacy 单上游（`--dns-upstream` 或
  `dns.upstream` 首项），以保持既有网关/脚本行为不变（写 `dns.routing` 即显式启用）。
- 未做（同表列明）：DoH h2/h3、ECS 透传、optimistic cache、`fixed_domain_ttl`、
  `ipversion_prefer`、`bootstrap_resolver`、sniff-punt。

## 后果

- **正面（实测）**：
  - `cargo test --release` **141/141**（dnsroute 5 项：编译/选择、AND+NOT、
    应答 ip/upstream、未知 tag 报错、无段返回 None）；
  - lab `dnsroute-up`+`test-dnsroute`：请求 reject（空应答且上游未见）、
    `qtype(https)` reject、`suffix: via2.test` → up2（up2 日志命中、up1 无）、
    同答缓存作用域（up2 仅 1 次上行）、fallback → up1、应答
    `ip(10.9.10.60/32)` reject（answer 清空、无重查）、应答
    `ip(10.9.10.61/32)` → up2 重查、`asis`（UDP 与 TCP 客户端，均回
    10.9.9.2:53 的 WAN ns 假 DNS）、`dns.routing` 热重载（fallback 即改即生效）；
    status `.dns.routing` 计数（rejects/response_rejects/relookups）与
    `.dns.upstreams` 全部断言；
  - 回归：`verify` 9/9、明文 DNS 三连（cache/tcp/edns）、`test-config-reload`
    （上游热切换）、`test-dot` 均过；规则对拍 `parity.sh` 5/5 逐字节（编译器未动）。
- **负面/代价**：`dnsroute` 为独立解释器（每次查询线性扫规则行；规则数通常个位，
  开销可忽略）；缓存键变长（作用域字符串）。
- **风险**：应答重查成环由深度上限兜底（≥3 放弃 + 日志 + `upstream_errors`），
  与 dae 同；`asis` 指向 mini 自身:53 的配置会自环（dae 文档同样警告），属配置错误。

## 验证方式（实测）

1. 单测：`cargo test --release`（dnsroute::*）。
2. lab：`sudo lab/lab.sh dnsroute-up && sudo lab/lab.sh test-dnsroute`。
3. 回归：`verify`、`test-dns-cache`/`test-dns-tcp`/`test-dns-edns`、
   `test-config-reload`、`test-dot`、`parity.sh`。

## 修订条件

- DoH h2/h3、ECS、optimistic cache/fixed_domain_ttl/ipversion_prefer 落地时；
- 需要 dae 的 `sub/node/subnode` 内部查询语义（mini 引入订阅拉取/节点域名走 DNS
  路由时）时；
- `ip(geoip:…)` 需要 trie 或大规则集时；或 `dns.upstream` 需要按 tag 保序选择策略时。
