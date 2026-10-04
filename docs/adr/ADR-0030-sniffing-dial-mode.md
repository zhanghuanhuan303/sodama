# ADR-0030：用户态嗅探 + dial_mode（远端域名解析，P14）

- **状态**：已采纳（2026-10-04）
- **对应**：P14；补对标表缺口 #1「嗅探与域名策略（dial_mode）」
- **相关**：ADR-0029（真网关）、ADR-0017（vless/vmess 目标编码）、ADR-0028（SOCKS 入口）、NOTES §11.21

## 背景

- 对标清点中「嗅探 + dial_mode」被列为第一缺口：dae 在内核侧做 TCP 嗅探
  （`sniffing_timeout` 默认 30ms，读首载荷判 TLS/HTTP），`dial_mode: domain/domain+`
  把**嗅探到的域名**而不是 IP 交给代理节点远端解析——这是绕开本地 DNS 污染的关键。
- sodama 此前 target 一律 IPv4（`SocketAddr`），浏览器走真网关时若本地 DNS 被污染，
  TLS 会连到错误 IP，只能靠浏览器 Secure DNS/DoH 规避。

## 决策

1. **目标地址类型化**：新增 `target::Target`（`Ip(Ipv4Addr,port)` / `Domain(String,port)`），
   域名编码逐协议对齐既有规格：
   - RFC1928 风格（ss / socks5 dialer / trojan / anytls）：`0x01`=IPv4、`0x03`=域名（len+name）；
   - vless / vmess：`0x01`=IPv4、`0x02`=域名；
   - tuic v5：`0x00`=域名、`0x01`=IPv4；
   - hysteria2：`"host:port"` 字符串；
   - direct / 回退路径：`resolve_local()`（优先 IPv4）。
   UDP 目标仍为 `SocketAddr`（UDP 域名目标与 QUIC 嗅探不在本 ADR 范围）。
2. **用户态嗅探**（`sniffer` 模块）：解析 TLS ClientHello SNI 与 HTTP/1.x Host / CONNECT；
   relay accept 后用 `MSG_PEEK` **只读采集**（不消费字节，泵语义不变），
   超时 `--sniffing-timeout-ms`（默认 100ms）。
3. **`--dial-mode ip|domain|domain+`**（`domain++` 为兼容别名）：CLI > config
   `global.dial_mode` > 默认 `ip`；仅当非 `ip` 时嗅探。命中 → 域名交节点；
   未命中/超时 → 按 IP（与旧行为一致）。`lab/gateway.sh` 默认 `domain`。
4. **SOCKS5 入口同享**：客户端给域名且 dial_mode != ip 时不再本地解析，域名直交节点。
5. **可观测**：状态面新增 `sniffing`（dial_mode / timeout_ms / attempts / hits / misses）。

## 理由

- 用户态 `MSG_PEEK` 方案零数据面改动、零信任边界变化；嗅探失败自动回退 IP，
  不会让「非 TLS/HTTP 客户端」变慢超过一个超时窗口；
- 默认 `ip` 保持既有 lab/回归零感知；面向真实网络的 gateway 脚本默认 `domain` 吃到收益；
- 逐协议域名编码与既有跨实现测试共用同一套对拍方法（可在 lab/真实节点直接验证）。

## 与 dae 的差异（如实）

- dae 嗅探在**内核侧**、支持 QUIC/UDP 嗅探与 sniff-punt（按嗅探域名重判路由）；
  本实现为 relay 侧用户态嗅探，不重判路由；QUIC/UDP、HTTP/2 明文（h2c）不做。
- dae 的 `domain` 模式带「本地 DNS 缓存/后台探测门槛」，`domain+` 跳过；
  本实现 `domain` 即「命中即用域名」（等价 dae `domain+` 的行为），`domain+` 为别名。
- ClientHello 跨多条 TLS record 只解析首 record（超时回退 IP，不阻塞）。

## 后果

- **正面（实测）**：
  - lab：`DIAL_MODE=domain REAL_NODE_URL=anytls://… sudo lab/real-node-e2e.sh`
    → 日志 `sniff 203.0.113.34:443 → www.gstatic.com（域名交节点远端解析）`、HTTP **204**、
    relay `dial_errors=0`；
  - 真机（Arch / wlan0 / anytls 节点）：`gateway.sh up`（默认 domain）→
    状态面 `sniffing: attempts=10 hits=10 misses=0`、gstatic 204 / YouTube 200 /
    出口 IP 节点侧、`down 1.2MB`。
- **负面/代价**：domain 模式下若客户端首包不像 TLS/HTTP，最多增加
  `sniffing-timeout-ms` 的拨号等待（默认 100ms，仅连接建立时一次）；
  h2c/QUIC 不回退域名；域名解析失败 = 连接失败（无本地二次解析，保持「远端解析」语义）。
- **风险**：误解析会把错误域名交节点；已用单测钉住常见形态，且非 TLS/HTTP 一律 IP 回退。

## 验证方式（实测）

1. 单测：`sniffer` 8 项（SNI / 分段 NeedMore / 无 SNI / HTTP Host / 半包 / 无 Host /
   CONNECT / 二进制否定）、`target` 4 项（编码/解析/解析本地）、vless 域名头 1 项；
   `cargo test --release` **108/108**。
2. 跨实现（lab netns + 真实节点）：见「正面」第 1 条。
3. 真机网关 + 状态面计数：见「正面」第 2 条；`sniffing.hits` 与 `relay.conns_total` 一致增长。

## 修订条件

做 QUIC/UDP 嗅探、h2c 嗅探、sniff-punt（域名重路由）、或引入 dae 式
「DNS 缓存门槛」语义时，新写 ADR 扩展；若真实节点对域名目标兼容性出现系统性问题，
把默认值回退策略写入本 ADR 修订版。
