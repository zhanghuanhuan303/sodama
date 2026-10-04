# ADR-0012：P3a 范围与边界——透明 UDP DNS 接管 + 域位图，domain 规则转可编译

- **状态**：已采纳（2026-10-03）
- **对应**：ADR-0009 的 P3（DNS）第一阶段（P3a）
- **相关**：ADR-0005（配置 100% 兼容）、ADR-0011（K3 的显式 deferred）

## 背景

K3 把 `domain(…)` 规则整条列入 deferred，原因是没有域位图（DNS 应答 → IP → 规则位图）
就无从匹配。P3 要做 DNS，但 dae 的 DNS 栈相当宽：缓存、`dns.routing` 请求/应答分流、
DoH/DoQ、TCP DNS、`geosite` 数据、`regex:` 域匹配、sniffing punt（`ROUTE_STATE_DNS_QUERY`
把 DNS 强制拉进控制面）等。若一次全做，周期长且验证面难收敛；若只做一半又不写清边界，
就会出现「看起来支持 domain、实际只覆盖部分形态」的隐性错误。

因此 P3 拆为 P3a（本 ADR：最小闭环）与 P3b（缓存/加密 DNS/TCP/regex/嗅探 punt）。

## 决策

1. **P3a 只做透明 UDP DNS 接管**：数据面把 UDP:53 当普通 proxy 流量交给 tproxy
   socket（`sockmap` key 1）；加载器以 `IP_TRANSPARENT` 监听、用 `IP_ORIGDSTADDR`
   （recvmsg cmsg）取原始目的地址，转发到上游（`--dns-upstream` 或配置
   `dns.upstream`，缺省 `8.8.8.8:53`）。上游 socket 在 **host netns** 创建，
   避免上游查询被自己的钩子二次捕获。
2. **回包必须用绑定原始目的地址的独立 socket**：tproxy 语义下回包源地址是客户端
   当初的目的地址（非本机地址），直接用监听 socket 回包会在客户端侧呈现错误源。
   这是 P3a 实现里最容易踩错的一点，作为语义固定下来。
3. **域位图与 dae 同构**：
   - 规则侧 `domain(suffix:|full:|keyword: …)` 编译为 `DomainSet` 型 match_set，
     **位下标 = 该 domain 参数在数组中的位置**（对照 dae `addDomain`，
     `control/routing_matcher_builder.go:375`）；
   - 数据面 `domain_routing_map`（key = `{slot, ipv4-mapped addr}`，value = 位图
     `[SODAMA_MAX_MATCH_SET_LEN/32]`）对照 `tproxy.c:388`；匹配函数
     `sodama_route_match_domain_set` 对照 `tproxy.c:1673-1706` 的 word 缓存实现；
   - 用户态解析 DNS 应答的 A 记录，对每条 domain 规则做 suffix（**点边界**，
     即 `a.example.com` 命中 `example.com` 而 `notexample.com` 不命中）/full/keyword
     匹配，算出位图，经 mpsc 交主循环写 map（服务线程不碰 map）。
4. **生命周期与热重载对齐**：SIGHUP 重载时清理 `domain_routing_map` 非活跃槽
   （对照 dae `clearReloadDomainRoutingMapSlot`，`control/control_plane.go:986`）。
5. **P3a 显式边界**（未实现的一律不得假装支持）：
   - 只处理 UDP DNS；**TCP DNS 不支持**（计数，不接管）；
   - AAAA 只计数、不落位图（IPv6 路径整体未实现）；
   - 无 DNS 缓存、无 `dns.routing` 请求/应答分流、无 DoH/DoQ、无 `geosite`；
   - `domain(regex:)` 由「整条规则 deferred」改为显式 deferred，原因标注 regex
     未实现（规则级原子原则不变：绝不部分编译）。
6. **验收口径**：`proxy.test` 与 `direct.test` 两条域规则，DNS 经 sodama 转发到
   假上游后，前者 IP 命中 domain 规则走 tproxy、后者直转；状态面可见
   `dns.queries / published_ips / maps.domain_routing`。

## 理由

- 小闭环优先：UDP DNS 覆盖了家庭/办公网络绝大多数场景，先把「DNS 应答 → 位图 →
  规则匹配」这条链在数据面打通，后续 P3b 加缓存/加密 DNS 都只是在同一模块上加功能。
- 与 dae 逐条对照（map 结构、位下标、word 缓存、槽清理），保证将来行为对拍时
  domain 语义不发生漂移。
- 边界显式列出并进入计数器/状态面，避免「配置能写 domain 却只有部分形态生效」
  这类隐性错误。

## 后果

- 正面：`domain` 规则从 deferred 转为可编译；`lab/real-user.dae` 的
  `domain(suffix: example.com)` 已生效（supported 6 / deferred 1）；
  域位图给出 P3b 与 geo/geosite 的接入点；状态面新增 `dns` 段与
  `maps.domain_routing`，DNS 行为可观测。
- 负面/代价：DNS 线程与主循环之间新增一条 `MainMsg::DnsPublish` 写路径（仍满足
  「主循环独占 `Ebpf`」约束）；应用只走 TCP DNS 或 DoH 的环境下 P3a 不生效
  （显式计数，不静默）；无缓存意味着每条查询都直连上游，性能不是 P3a 目标。
- 风险：`IP_ORIGDSTADDR` 与 `IP_TRANSPARENT` 组合对内核配置敏感（需要
  `transparent`/路由配方与 TCP 侧一致）；lab 已固化该配方，实际部署需在安装阶段
  同样检查。

## 验证方式（实测）

- `cargo test --release`：17/17 通过，其中 P3a 新增覆盖 DNS wire 查询解析
  （压缩指针、CNAME、AAAA 计数）与 A 应答构造、域名匹配（suffix 点边界/full/keyword）
  及位图计算。
- `lab.sh dns-up && lab.sh test-domain`：
  ```
  answer=10.9.10.3 / answer=10.9.10.4         # DNS 经 sodama 转发到假上游
  sodama tproxy: orig_dst=10.9.10.3:9999    # proxy.test 的 IP → domain 规则命中
  wan-echo-ok data=ping                       # direct.test 的 IP → 内核直转
  dns: queries=2 published_ips=2 domain_routing_entries=2
  PASS: 域位图端到端（DNS 接管 → 位图 → domain 规则分流）
  ```
- `lab.sh config-up && test-config`：`supported=6 deferred=1`（仅 geoip 仍 deferred）；
  `status` 返回 `rules=12` 与顶层 `dns` 段。
- `lab/parity.sh`：规则编译与 dae 原版 Go 编译器逐字节一致（domain 位下标随位置
  生成，对拍覆盖）。

## 修订条件

P3b 落地（DNS 缓存 / DoH / DoQ / TCP DNS / `domain(regex:)` / 嗅探 punt）时，新写
ADR 取代本条对边界部分的描述；`geosite` 与 geoip 接入属 geodata 轨道，另条记录。
若将来内核侧改为 dae 的 DNS 强制控制面路径（`ROUTE_STATE_DNS_QUERY`），需重新评估
「DNS 作为普通 tproxy 流量」这一前提。
