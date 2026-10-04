# ADR-0047：P23——sticky IP + DoH h2 + bootstrap_resolver + DNS 选项

- **状态**：已采纳（2026-10-04）
- **对应**：对标表缺口 #2（sticky IP）、#5（DoH h2 / optimistic cache / fixed_domain_ttl /
  ipversion_prefer / bootstrap_resolver）
- **相关**：ADR-0031（订阅/组）、ADR-0034/0035（DoT/DoH/DoQ）、ADR-0043（多组分派）、
  NOTES §11.38；对照 dae `StickyIpDialer`、`dns_control.go`、`global.bootstrap_resolver`

## 背景

- **粘滞 IP**：代理服务器地址是域名时，每次拨号重解析会因 DNS 轮询/污染换 IP，
  同一节点时好时坏。dae 对域名地址套 `StickyIpDialer`（`sticky_cache.go`）：
  钉住 IP，连续失败 3 次才作废重解析，成功清零，reload 重置全局状态。
- **DoH h2**：RFC 8484 要求 h2/h3；P18a 的 DoH 是 HTTP/1.1（主流公共 DoH 兼容，但
  非标准形态）。dae 走 Go net/http2。
- **bootstrap_resolver**：解析「解析本身可能被数据面接管」的域名（DNS 上游主机名、
  订阅/节点主机名）需直连指定解析器；此前用 IP 字面量规避。
- **DNS 选项**：dae 的 optimistic cache（过期窗口内 stale 供应）、`fixed_domain_ttl`
  （缓存寿命覆盖，0=立即过期）、`ipversion_prefer`（已知首选族时非首选族回空应答）。

## 决策

1. **sticky.rs**（新）：`resolve(hostport)`（IP 字面量直通；域名→粘滞条目，TTL 600s）、
   `note_dial(addr, ok)`（连续 3 次失败作废、成功清零，反向索引 addr→key）、`reset()`
   （reload 调用，对照 `ResetGlobalProxyStateForReload`）。接入 `outbound::resolve`
   与 `dial_tcp`/`dial_udp` 的 `server_addr()` 结果反馈。
2. **DoH h2**（h2client.rs 新 + dnsup 改造）：
   - 最小 HTTP/2 客户端：前言+SETTINGS 握手、HEADERS（HPACK 静态索引 + 非 Huffman
     literal）、DATA 流控（WINDOW_UPDATE）、SETTINGS/PING/GOAWAY/RST/CONTINUATION 处理，
     响应解析 `:status`（静态索引/字面量/Huffman 值）；
   - `tls::connect_alpn` 暴露协商 ALPN：ALPN=h2 才发前言；HTTP/1.1-only 服务端**同一
     连接直接走 H1**（不再白送一次失败握手）；ALPN=h2 但握手失败 → 标记该上游
     `h2_broken` 并回退 H1（连接/请求两级重试）。
3. **bootstrap.rs**（新）：`global.bootstrap_resolver`（可逗号分隔；支持 scheme 前缀，
   未配置=不启用）。查 A+AAAA（UDP，TC=1 走 TCP），SO_MARK 直连；接入
   `dnsup::Upstream::new`（上游主机名）与 `subscribe::fetch`（订阅主机名）；
   启动与 reload 均热更新。
4. **DNS 选项**（dns.rs/main.rs/config.rs）：
   - optimistic cache：`optimistic_cache`（默认 true）、`optimistic_cache_ttl`（默认 60，
     0=不限）、`optimistic_stale_reply_ttl`（默认 30）——过期条目在窗口内以 stale 供应，
     记录 TTL 压到上限；`sweep_expired` 同样尊重窗口；
   - `fixed_domain_ttl { 域名: 秒 }`：命中域名用固定缓存寿命（0=立即过期，配合
     optimistic 可供 stale）；config 校验放行该子段；
   - `ipversion_prefer: 4|6`：非首选族查询且缓存中已有未过期首选族答案 → 回空
     NOERROR（`has_fresh`）；仅 AAAA 的域名不受影响；
   - 状态面新增 `optimistic_cache/stale_hits/ipversion_prefer/ipversion_filtered/fixed_domain_ttl`。

## 理由

- sticky 语义按 dae 可观察行为近似（条目 TTL + 失败阈值），不引入健康检查周期维度；
  失败反馈集中在 `Outbound::dial_tcp/dial_udp` 包装层，协议实现零改动。
- h2 自实现（≈470 行）避免引入 h2/http 依赖栈；HPACK 编码只用静态表 + literal，
  服务端（Go/nginx/公共 DoH）均接受；ALPN 门控让 H1-only 服务端零额外连接。
- bootstrap 仅「显式配置才启用」：与 dae 的 119.29/223.5 默认回退不同（如实记录），
  避免在非中国大陆环境把解析悄悄改道。

## 后果

- 正面：域名节点不再抖动、失败自动换 IP；DoH 达 RFC 8484 的 h2 形态且兼容 H1；
  启动期上游/订阅域名可自举解析；DNS 缓存行为对齐 dae 三选项。
- 负面/边界：sticky 不含健康检查周期刷新与协议/IP 版本维度缓存；DoH h2 未实现
  服务端推送（拒收）、动态表解码（`:status` 之外的编码形式尽力而为，DNS 报文特征兜底）；
  optimistic 无后台刷新（stale 服务后由下次查询自然刷新）；bootstrap 未启用时不改变
  系统解析行为。

## 验证方式

- 单测（**202/202**）：sticky 6 项（粘滞复用/IPv4 优先/3 次失效/成功清零/TTL/IP 直通）、
  bootstrap 3 项（查询构造/配置解析/本地假 DNS 环回 A+AAAA）、h2client 4 项
  （HPACK 编码字节、整数、`:status` 索引/字面量）、dns 缓存 3 项（stale TTL 上限与窗口、
  fixed=0+optimistic、has_fresh 过期与类型）。
- lab：
  - `doh-h2-up` + `test-doh-h2`：Go 标准库 h2 参考服务端（仅收 h2，ALPN 日志为证），
    两次查询复用一条连接、loader 无回退日志；
  - `doh-up` + `test-doh`（Python HTTP/1.1 服务端）：连接数=1（ALPN 门控生效），
    DoT 回归 PASS；
  - `dnsopts-up` + `test-dns-options`：首查 TTL=30（上游值，fixed 只改缓存）、
    2s 后第二次查询 stale TTL=7 且上游恰好 1 次、AAAA 被过滤（ancount=0）、
    仅 AAAA 域名原样返回、状态面计数。
- 真机：网关重启自检通过（66/66 alive、代理 204、0 panic）；sticky 在 reload 重置日志可查。
- 文档：本 ADR + parity v2.2 + HTML v2.32 + NOTES §11.38。
