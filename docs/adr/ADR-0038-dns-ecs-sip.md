# ADR-0038：DNS 精细策略——上游 ECS 注入（`ecs=auto`）+ 客户端网段路由（`sip()`）

- **状态**：已采纳（2026-10-04）
- **对应**：P18c 实用化扩展（二）：国内域走 DoH 时的 CDN 精度、按客户端来源分流
- **相关**：ADR-0036（`dns.routing`）、ADR-0037（`qname(file:)`）、NOTES §11.29；
  上游对照：dae 只透传客户端自带 EDNS（`control/dns_control_optimistic.go:57`
  注释），DNS 请求路由函数仅 qname/qtype——本 ADR 两项均为 **sodama 扩展**

## 背景

- 真网关把国内域交给本地路由器明文（`router`）后，国外域走 DoH；但用户希望
  「国内域也走 DoH」——此时上游只看递归出口 IP，CDN 会按递归机房选址，
  对国内小运营商出口可能偏。ECS（RFC 7871）能把**客户端子网**随查询带给上游，
  让权威侧按真实位置作答。
- 另一个需求是**按客户端网段分流**：不同来源（如访客网段/本机）走不同上游。
  dae 的 DNS 请求函数没有 `sip` 之类来源匹配（只有主路由有），故为 sodama 扩展。

## 决策

1. **ECS 注入：上游 URL 参数 `ecs=auto|<IP>/<prefix>`**（`dnsup.rs`）：
   - `auto`：按查询发起方地址归整——v4 `/24`、v6 `/56`（RFC 7871 常见实践）；
   - 显式前缀：`ecs=192.0.2.0/24` / `ecs=2001:db8::/56`（校验越界）；
   - 注入在 `resolve_dns` 发送前（`dns::add_ecs`，尾插 OPT + ECS option 8，
     RDLEN 与 option-length 分列）；**客户端自带 OPT/ECS 时不动**（透传）；
   - 注入生效时缓存作用域追加 `|ecs=<前缀>`（不同子网不互串答案）；
   - 应答路由的换上游重查也按新上游的 ECS 配置重新注入。
2. **客户端网段路由：请求函数 `sip(...)`**（`dnsroute.rs`）：
   - 值同 `ip()`：裸 CIDR / `geoip:` / `ext:`；`!sip(...)` 取反；
   - 与 `qname/qtype` 同链参与 `&&`/`||` 语义与 fallback；
   - 无客户端信息来源时不命中（`!sip` 命中）；
   - 客户端地址：UDP 路径取 `recvmsg` 的源地址；TCP 路径取 `peer_addr()`。
3. **真网关默认**（`lab/gateway.dae`）：新增 `alidns_ecs`
   （`https://223.5.5.5/dns-query?sni=dns.alidns.com&ecs=auto`），
   `qname(geosite:cn) -> alidns_ecs`；`router` 保留在清单里一键可切。
4. **可观测/测试**：假上游（`fake_dns.py`）解析 OPT 中的 ECS 并在日志行附
   `ecs=1/24/10.0.0`（地址按前缀截断），lab 据此断言注入内容与截断语义。

## 理由

- ECS 放上游 URL 而非规则注解：实现面小（无解析器改动）、语义清晰
  （“这条上游带 ECS”），且与 `qname(file:)` 等规则天然组合（换上游即换 ECS 策略）。
- `sip` 复用响应侧已有的 CIDR 匹配/展开代码（`ip_set`/`ip_hits`），
  零新数据结构，且 `geoip:` 直接可用（如 `sip(geoip:private)` 区分内网来源）。
- 作用域化缓存键是必须的：ECS 答案按子网定制，若共享缓存会互相污染。

## 与 dae 的差异（如实）

- dae 不主动注入 ECS；`sip` 不存在于其 DNS 请求路由。两项均为 sodama 方言扩展
  （dae 原版配置不受影响）。
- ECS 仅在查询**无 OPT** 时注入；客户端自带 OPT（含 ECS）时保持透传——
  与 dae 的透传语义一致，也避免同一报文出现两个 ECS 选项。

## 后果

- **正面（实测）**：
  - `cargo test --release` **145/145**（ECS 编码/截断/已带 OPT 不动、
    `ecs_auto_prefix` v4/v6、`sip` 匹配含反例）；
  - lab `test-dnsroute`：`ecs=auto` 上游收到 `ecs=1/24/10.0.0`（客户端
    10.0.0.2，地址按前缀截断）；`qname(...) && sip(10.0.0.0/24) -> up2`
    命中（up2 日志）；7 条请求规则矩阵 + `upstream_hits` 断言全过；
  - 真机网关：`upstream_hits {alidns: 78, alidns_ecs: 8}`、86 查询 0 错误、
    国内/海外解析正常（DoH+ECS 路径真实可用）。
- **负面/代价**：注入 ECS 的查询缓存按子网拆分（内存条目增多）；
  向公共 DoH 暴露客户端子网（隐私权衡，`ecs=` 可随时去掉）。
- **风险**：部分 DoH 上游忽略/剥离 ECS（答案回落为普通解析，无错误）；
  `auto` 的 /24、/56 是常见粒度，可按需在 URL 里显式指定。

## 验证方式（实测）

1. 单测：`cargo test --release`（`ecs_injection_shape_and_auto_prefix`、
   dnsup 的 `ecs=` 解析、`request_sip_client_subnet`）。
2. lab：`sudo lab/lab.sh dnsroute-up && sudo lab/lab.sh test-dnsroute`。
3. 真机：`sudo lab/gateway.sh up --config lab/gateway.dae --geodata-dir /usr/share/v2ray
   --subscribe /tmp/sodama-sub.url`；`status .dns.routing.upstream_hits`。

## 修订条件

- 需要 per-rule ECS（同一上游对不同域名用不同 ECS）时，改为规则注解；
- 需要 ECS 响应回填客户端（RFC 7871 应答侧 scope 处理）或 ECS 缓存
  （`ecs_cache`）时；
- `sip` 需要出现在应答路由（按请求来源过滤应答）时。
