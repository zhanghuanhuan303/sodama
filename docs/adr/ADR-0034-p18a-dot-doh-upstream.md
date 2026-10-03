# ADR-0034：P18a DNS 安全上游——DoT/DoH 传输 + 上游抽象

- **状态**：已采纳（2026-10-04）
- **对应**：P18（对标表缺口 #5「DoH/DoQ + `dns.routing`」）之 **a 段**；P18b DoQ、P18c `dns.routing` 待做
- **相关**：ADR-0012/0013/0014（明文 DNS、缓存、regex/EDNS）、ADR-0021（状态面）、
  NOTES §11.25；上游对照 `component/dns/upstream.go`（scheme/默认端口/`tcp+udp` 语义）

## 背景

- 对标表缺口 #5：dae 的 DNS 上游支持 `udp`/`tcp`/`tcp+udp`/`tls`(DoT)/`https`(DoH)/
  `quic`(DoQ)/`h3`(DoH3) 七种 scheme，并把上游当一等对象（`dns.upstream` 是
  tag→url 的 map）。mini 此前只把它当 `host:port`，且**客户端入口协议顺带决定上游
  传输**（TCP 客户端 → TCP 上游）——与 dae 不一致。
- 上游语义（研究结论）：无 scheme 或 `tcp+udp`/`udp+tcp` → **UDP 优先，应答 TC 位或
  失败再走 TCP**；`udp`/`tcp`/`tcp+udp` 默认端口 53；`tls`/`quic` 默认 **853**；
  `https`/`h3` 默认 **443**、默认 path `/dns-query`；上游是 hostname 时 dae 要求
  `global.bootstrap_resolver`（解析上游本身需要 DNS 的鸡生蛋问题）。
- 传输形态：DoT = TLS + 2 字节长度分帧（RFC 7858），连接可复用；DoH =
  HTTPS POST `application/dns-message`（RFC 8484），连接可复用（keep-alive）。

## 决策

1. **上游抽象**（新模块 `loader/src/dnsup.rs`）：`UpstreamSpec{scheme,host,port,path,
   sni,insecure}` + `parse()`（`[v6]`、`?sni=`、`?insecure=1`）+ `Upstream::new()`
   （主机名解析**优先 IPv4**——marked socket 为 AF_INET；UDP socket 用
   `outbound::new_marked_udp()`，TCP 用 `marked_tcp_connect()` 保持 SO_MARK，
   DNS 出站不回流自己的钩子）+ `exchange(query) -> Result<Vec<u8>, String>`。
   默认端口/默认 path 与 dae 逐项对齐；`h3://` 显式报错（不做静默降级）。
2. **传输实现**：
   - `udp`：共享 marked UDP socket，锁内串行（避免并发响应串包），按 DNS ID 跳过
     杂包；`tcp+udp` = 先 UDP，**应答 TC 位或出错再 TCP**（不再看客户端协议）；
   - `tcp`：每查询一条 marked TCP，2 字节分帧；
   - `tls`：**持久连接**（锁内串行 + 30s 空闲重建 + 失败丢弃重连一次），2 字节分帧；
   - `https`：持久连接 + **HTTP/1.1 POST `application/dns-message`**，
     支持 Content-Length/chunked 响应体，失败重连一次。
3. **接入主流程**（`main.rs`）：全局 `UPSTREAM: Mutex<Option<Arc<Upstream>>>` 取代
   `UPSTREAM_ADDR`；客户端侧枚举改名 `ClientProto{Udp,Tcp}`（只决定应答截断，
   不再影响上游传输）；`resolve_dns` 统一走 `upstream.exchange()`；`--dns-upstream`
   接受完整 URL；`dns.reload`/SIGHUP 时**重建 Upstream 并按 URL 比较热切换**；
   状态面新增 `dns.upstream_url`/`dns.upstream_scheme`（`dns.upstream` 保留解析后的
   地址串，兼容既有脚本）。
4. **配置**：`dns.upstream { tag: 'url' }` 仍取第一个（多上游选择留给 P18c）；
   上游 URL 允许带 scheme；`global.bootstrap_resolver` 暂不实现——上游主机名在
   启动/重载时经**系统解析器**解析一次（差异见图）。
5. **lab 夹具**：`lab/dns_transport_server.py`（Python `ssl`，tls/https 两种模式，
   自签证书来自 `lab/certs/`，转发到假 UDP DNS 并按传输打日志）；假 DNS 新增
   `dot/dot2/doh/doh2/udpup/tcpup.test` 夹具；会话 `dot-up`/`doh-up`/`dns-udp-up`/
   `dns-tcpup-up` + 测试同名单（`TLS-CONN`/`DOH-CONN` 计数断言**连接复用**）。

## 理由

- 上游传输与客户端入口解耦，语义回到 dae 的 `tcp+udp`（UDP 优先的 TC 回退），
  同时修掉旧行为里「TCP 客户端→TCP 上游」的隐性放大（每个 TCP 查询一条上游连接）。
- DoT/DoH 用**持久连接**是低风险高收益：与 dae 一致，省握手；锁内串行在单
  dns_loop 线程的实际使用下无争用，且天然避免了流复用下的响应错配。
- 复用既有 TLS 栈（`tls.rs`，rustls）+ 既有 marked socket 工具，零新依赖；
  `insecure=1` 与其它协议一致（self-signed lab）。
- 状态面/热切换沿用 P6 机制，运维零新增概念。

## 与 dae 的差异（如实）

- **DoH 用 HTTP/1.1**：RFC 8484 名义要求 h2/h3；实测公共 DoH（AliDNS/Google 等）
  均接受 HTTP/1.1，本版按 HTTP/1.1 实现（含 chunked 解析）。h2 需要 HPACK
  编码侧（现有 `hpack.rs` 只有解码与 QPACK 静态表，h3 认证用），列为修订条件。
- **`h3://`（DoH3）未实现**（显式报错，不降级）；`quic://`（DoQ）P18b。
- **上游主机名解析**：dae 用 `bootstrap_resolver` 在内部解析（可走自己的 DNS 链）；
  mini 用系统解析器在启动/重载时解析一次，此后固定 IP。若上游域名被污染，mini 会
  解析失败/解析到坏 IP——用 IP 字面量 + `?sni=` 可完全规避（已验证公共 DoT/DoH）。
- **`dns.upstream` 多 tag** 仍取第一个；该 config 段没有 tag 级引用语义（P18c 的
  `dns.routing` 才需要）。
- `udp://` 上游是 mini 的严格单 UDP（dae 同名 scheme 亦为纯 UDP）；历史上 mini 把
  `udp://` 当纯前缀剥掉，属旧差异，现已对齐。

## 后果

- **正面（实测）**：
  - `cargo test --release` **135/135**（新增 dnsup 单测：scheme/默认端口/URL 解析、
    HTTP 响应解析 length/chunked/非 200、TCP 分帧/TC 位）；
  - lab：`dot-up`+`test-dot`（2 次查询复用 1 条 TLS 连接、状态面 scheme=tls）、
    `doh-up`+`test-doh`（keep-alive 复用、path=/dns-query 记录）、
    `dns-udp-up`+`test-dns-udp`（仅 UDP 上行）、`dns-tcpup-up`+`test-dns-tcpup`
    （仅 TCP 上行；与 UDP 日志逐条区分）；
  - 明文 DNS 回归：`dns-up`+`test-dns-cache`/`test-dns-tcp`/`test-dns-edns` 全过
    （`test-dns-tcp` 已按新语义断言「TCP 客户端 → tcp+udp 上游走 UDP」）；
    `test-config-reload` 全过（上游 URL 热切换、回滚保留）；
  - 真实公网：DoH `https://223.5.5.5/dns-query?sni=dns.alidns.com` 与 DoT
    `tls://223.5.5.5?sni=dns.alidns.com` 在 lab 拓扑内解析 `www.baidu.com`/
    `www.qq.com` 成功（真实 A 记录、证书校验通过、`upstream_errors=0`）；
  - 回归：`verify` 9/9、规则对拍 `parity.sh` 5/5 逐字节（编译器未动）。
- **负面/代价**：DoT/DoH 持锁串行——单 dns_loop 线程下无实际排队；若未来 DNS
  线程池化，需要按连接/多路复用重构（与 P18c 的选择逻辑一并考虑）。
- **风险**：HTTP/1.1 公共 DoH 的普适性（已实测 2 家）；上游域名经系统解析器
  （见差异）。

## 验证方式（实测）

1. 单测：`cargo test --release`（dnsup::* 4 项）。
2. lab：`dot-up`/`test-dot`、`doh-up`/`test-doh`、`dns-udp-up`/`test-dns-udp`、
   `dns-tcpup-up`/`test-dns-tcpup`、`dns-up`+3 项明文回归、`ops-reload-up`+
   `test-config-reload`。
3. 真实公网：lab 拓扑 + 公共 DoH/DoT（见上）。
4. 回归：`verify`、`parity.sh`。

## 修订条件

- DoQ（P18b）与 DoH h2/h3 落地时（HPACK 编码或复用 h3 栈）；
- `dns.routing`（P18c）需要多上游/tag 引用/按域名选上游时；
- 需要 `global.bootstrap_resolver` 语义（上游域名走 dae 自己的 DNS 链）时；
- DNS 处理线程池化需要并发复用连接（去锁）时。
