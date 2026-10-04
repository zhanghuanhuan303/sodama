# ADR-0016：P5 G1 范围与边界——原生协议栈第一梯（shadowsocks classic AEAD + trojan）

- **状态**：已采纳（2026-10-03）
- **对应**：ADR-0009 的 P5（协议栈）；ADR-0004 的「Dialer 梯度」第一梯
- **相关**：ADR-0011（过渡一跳 → 0015 升为 dialer）、ADR-0015（relay/UDP NAT/offload 基座）、ADR-0008（部署形态）

## 背景

P5 的目标是把 P4 的「过渡一跳」（`--forward socks5://`）替换为**原生协议栈**，按 ADR-0004
的梯度推进：`direct → socks5 → ss → trojan → …`。G1 定义第一梯的协议与边界：

1. dae 生态里最常用的两个协议是 shadowsocks 与 trojan，且**不需要 cgo/FFI 复用 Go 库**，
   可以纯 Rust 实现（ADR-0002/0004 的硬约束）；
2. 加密协议与 P4c 的内核 offload **天然互斥**：ss 的 AEAD 帧、trojan 的 TLS 记录都不能
   被 `sk_skb` 直接内核对拼（那会绕过封装/解封装），互斥必须写成显式语义而不是「碰巧没开」；
3. UDP 代理在 G1 只有 shadowsocks 支持（SIP004 UDP 包），trojan/socks5 没有 UDP——
   「不支持时怎么办」必须有明确语义（显式计数回退，而不是静默直连）；
4. 协议实现最容易被「自己和自己的单测」骗过，G1 的验收必须包含**跨实现对端**
   （独立实现的 Python 服务端）+ 大流量完整性。

## 决策

1. **shadowsocks（classic AEAD，SIP004）**：
   - 方法面：`aes-256-gcm`、`chacha20-ietf-poly1305`；密钥派生 = `evp_bytes_to_key`
     （MD5 链）→ HKDF-SHA1（`info="ss-subkey"`，salt 每方向独立随机 32B）；
   - TCP 分块：`[salt][AEAD(len 2B, BE)][AEAD(payload)]…`，nonce 为小端递增计数器
     （长度块与载荷各占一个 nonce）；**单块明文上限 0x3FFF**，读写两端都必须按此切块；
   - UDP：每包 `[随机 salt][AEAD(payload, nonce=0)]`，载荷 = SOCKS5 地址头 + 数据；
   - 不做 SIP022（2022 版 AEAD-2022），不解析 ss 插件（URL 里带 `plugin=` 直接拒绝）。
2. **trojan（TCP CONNECT over TLS）**：
   - rustls 0.23（ring provider，进程内 `install_default` 一次）+ webpki 根；
     `allowInsecure=1` 时用 `NoVerify`（仅实验/自签）；SNI 可配（默认取 URL 的 host）；
   - 握手头：`hex(SHA224(password)) + CRLF + 0x01(CONNECT) + ATYP + ADDR + PORT + CRLF`，
     ATYP 只做 IPv4（sodama relay 的目标恒为 IPv4）；之后双向透明；
   - 边界：不做 UDP ASSOCIATE（03）、不做域名目标（0x03）、不做 TLS close_notify
     半关闭语义（直接 FIN）；URL 只支持 `trojan://pass@host:port?sni=&allowInsecure=`。
3. **offload 与协议互斥（显式）**：`Outbound::supports_offload()` 只有 `direct`/`socks5`
   为真；ss/trojan 命中时**即使传了 `--offload` 也不注册 fast_sock**，数据始终走用户态
   协议层。验收用「会话开了 offload 但 `offloaded_total == 0` 且用户态字节数 ≥ 512KB」
   正面断言（`lab.sh ss-up`/`trojan-up` 特意带 `--offload`）。
4. **UDP 能力与回退**：G1 只有 shadowsocks 声明 `supports_udp()`；其余协议在 UDP NAT
   路径上显式走直连回退并计入 `udp_nat.direct_fallback`（有 dialer 但协议不支持时）；
   验收要求 ss 会话下 `sessions_proxied >= 1 且 direct_fallback == 0`。
5. **跨实现验收对端**：`lab/ss_server.py`（Python `cryptography` 独立实现 TCP+UDP）、
   `lab/trojan_server.py`（stdlib `ssl` 独立实现）——不复用 Rust 侧任何代码；两个服务端
   的上游 socket 与 Rust relay 一样打 `SO_MARK=0x233`（同 ADR-0015 的防自环理由，
   否则服务端自己的出站流量会被 sodama 二次捕获成环）。
   另有两个**本地复现器**（不依赖 netns，用本地 echo 目标）：`lab/ss_local_probe.py`、
   `lab/trojan_local_probe.py`，用于把协议层问题从拓扑问题里剥离。
6. **边界（sodama 明确不做，留给后续）**：VMess/VLESS/SOCKS5-UDP 等属 G2；uTLS/指纹、
   obfs/ws 传输、多用户/密码表、trojan 的 UDP、IPv6 目标均不在 G1；ss 不做 2022 版。
7. **验收口径**：
   - `test-ss` / `test-trojan`：小流量回显 + 512KB 随机数据逐字节一致；独立服务端日志
     出现 `TCP target=1.1.1.1:8080` / `CONNECT target=1.1.1.1:8080`；`dial_errors=0`；
     `offload_enabled=true` 但 `offloaded_total=0`（互斥）；
   - `test-ss-udp`：3 报文复用 1 会话、回包源 = 原始目的地址、`sessions_proxied>=1`、
     `direct_fallback=0`、服务端日志 `UDP target=2.2.2.2:9998`；
   - 回归：标准/单臂 verify 9/9、DNS 六专项、relay/offload/UDP 五专项、
     `config-up`+`status`、`forward-up`、`lab/parity.sh` 逐字节一致；`cargo test 33/33`。

## 理由

- ss/trojan 的 wire 格式不复杂，但**跨实现**才能暴露「本端自洽、他端不认」的帧错误
  （实测就抓到一个：服务端把 `recv(65536)` 的整块当一块加密，超出 `!H` 长度上限）；
- 互斥语义写成 `supports_offload()` 的显式判断 + 正面断言，避免以后加协议时
  「默默把 AEAD 流量塞进内核拼接」；
- UDP 回退用计数显式化（而不是静默直连），让「协议不支持」在测试里必然可见；
- TLS 用 rustls 而不是引入 openssl/FFI，符合 ADR-0002/0004 的纯 Rust 约束。

## 后果

- 正面：协议梯度的第一梯落地，`--dialer` 现在支持 `direct|socks5|ss|trojan`；
  relay/UDP NAT 的既有生命周期（janitor、bytes、状态面）对协议流量原样生效；
  状态面新增 `dialer=ss://<method>@host:port` / `trojan://host:port`、
  `udp_nat.sessions_proxied` / `direct_fallback`，协议路径可观测。
- 负面/代价：ss/trojan 每连接两条用户态线程 + AEAD/TLS 状态，吞吐低于 offload 路径；
  trojan 无 UDP；ss 只做 classic，2022 版/插件生态不覆盖；`allowInsecure` 只应出现在实验。
- 风险：ss/trojan 都**不能**开启 offload，若未来要「协议感知的内核拼接」需重写数据面
  verdict 逻辑——那是新 ADR 的事，本 ADR 只说「现在不做，且不允许静默做」。
- 实现级坑（已修，写入 NOTES §11.6）：rustls 的明文缓冲默认仅 16KB，读路径必须保证
  「两次 `read_tls` 之间先抽干 `reader()` 明文」，否则大流量必现 `read_tls` 报错拆连接
  （修法：pending 密文缓冲 + 一次喂一块）。

## 验证方式（实测）

- `cargo test --release`：33/33（新增 `evp_bytes_to_key` 参考向量、ss UDP 回环、
  ss 流回环（同一主密钥）、trojan `password_hash` 向量、`SsMethod` 解析）。
- `lab.sh ss-up && lab.sh test-ss`：`stream-ok bytes=524288`；
  `ss tcp: conns=2 bytes_up=524299 bytes_down=524333 offloaded=0`；
  服务端日志 `TCP target=1.1.1.1:8080`。
- `lab.sh trojan-up && lab.sh test-trojan`：`stream-ok bytes=524288`；
  `trojan tcp: conns=2 bytes_up=524299 bytes_down=524333 offloaded=0`；
  服务端日志 `CONNECT target=1.1.1.1:8080`。
- `lab.sh ss-udp-up && lab.sh test-ss-udp`：`summary=3/3`；
  `ss udp: sessions=1/1 proxied=1 fallback=0 bytes_up=180 bytes_down=66`；
  服务端日志 `UDP target=2.2.2.2:9998`。
- 本地复现器：`ss_local_probe.py` / `trojan_local_probe.py`（Python 客户端 + 本地 echo，
  512KB 回显一致）——协议层问题可脱离 netns 定位。
- 回归：标准/单臂 `verify` 9/9；`test-domain`/`test-dns-cache`/`test-dns-tcp`/
  `test-dns-reload`/`test-domain-regex`/`test-dns-edns` 全过；
  `test-relay`/`test-relay-idle`/`test-relay-offload`/`test-udp-relay`/`test-udp-idle` 全过；
  `test-config`/`test-status`/`test-forward` 全过；`lab/parity.sh` 两份规则集逐字节一致。

## 修订条件

G2（VMess/VLESS 等）落地时新写 ADR 扩展梯度，不改本 ADR 的 G1 结论；若需要 SIP022、
trojan UDP 或协议感知 offload，另写 ADR 取代本条第 1/2/3 点的对应部分；若跨实现对端被
换成真实客户端（如 ss/trojan 官方实现），把「独立实现」约束放宽为「外部实现」即可。
