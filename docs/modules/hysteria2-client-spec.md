# hysteria2 客户端字节级协议规格

> 研究对象：`github.com/olicesx/outbound@v0.0.0-sticky-ip.0.20260918090140-cc86ced2e683`（dae 使用的 outbound 分支）。
> 用途：Rust（quinn 0.11）重写客户端 + Go（quic-go fork + http3）独立参考服务端交叉验证（`lab/proto-check/hy2-server`）。
> 证据等级：**源码实测**（阅读源码得出）｜**测试实测**（仓库自带测试的行为）｜**推断**（未验证）。
> 路径缩写：
> - `hy2/` = `protocol/hysteria2/`
> - `client/` = `hy2/client/`，`internal/` = `hy2/internal/protocol/`
> - `dialer/` = `dialer/hysteria2/`
> - `quic/` = `github.com/olicesx/quic-go@v0.0.0-20260910141758-62d80bbebb5b/`
> - 本文所有 `文件:行号` 都相对上述缩写。

## 0. 总览

hysteria2 = **一条 QUIC 连接**上跑三样东西：HTTP/3 认证、TCP 代理流帧、UDP 代理 datagram。

| 层 | 承载 | 关键点 |
|---|---|---|
| QUIC | ALPN `h3`、TLS1.3、`EnableDatagrams` 双向 | keepalive 5s / idle 60s（`client/config.go:23-24`） |
| 认证 | HTTP/3 POST `/auth`（control 单向流 + 一条双向流） | 成功状态 **233**（不是 200） |
| TCP | 每条 relay 连接一条 QUIC 双向流 | 首帧 `0x401`；半关闭 = FIN |
| UDP | QUIC DATAGRAM | `SessionID/PacketID/FragID/FragCount` + 地址 + 数据 |
| 混淆（可选） | QUIC 之下、UDP 之上，逐 datagram | salamander：`[salt][XOR]` |
| 拥塞控制（可选） | QUIC 内部 | Brutal 固定速率（客户端本地选择，无线上协商） |
| 端口跳变（可选） | 本地 socket/目标端口轮换 | udphop：对 QUIC 谎报地址 |

固定项：QUIC `MaxIdleTimeout` 限 [4s,120s]、`KeepAlivePeriod` 限 [2s,60s]，缺省 60s/5s
（`client/config.go:77-86`）；`EnableDatagrams` 恒真（`client/client.go:129`）。

## 1. 链接 / 配置

解析入口 `dialer/hysteria2.go:160-245`（`ParseHysteria2URL`），链接形如：

```
hysteria2://<auth>@host:port[s,s2-s3]?sni=&insecure=&pinSHA256=&ca=&ech=&maxTx=&maxRx=#name
hy2://…（别名，`dialer/hysteria2.go:26-27` 同时注册）
```

| 参数 | 含义与默认 | 来源 |
|---|---|---|
| URL user/password | auth 串：`user:password`（两者都百分号解码后拼回 `:`）；缺省空串 | `dialer/hysteria2.go:236-245` |
| host:port | `host:port`，port 可为并集（见 §6 udphop） | `dialer/hysteria2.go:80-91` |
| `sni` | `ServerName`；空则由协议层回退主机名（**推断**：本仓库直接传空串） | `dialer/hysteria2.go:234` |
| `insecure` | `strconv.ParseBool` 接受集合；或全局 `AllowInsecure` | `dialer/hysteria2.go:174-180` |
| `pinSHA256` | 叶证书 SHA256 固定（十六进制，忽略 `:`/`-`）；置位时跳过链验证 | `dialer/hysteria2.go:112-137` |
| `ca` | 自定义根证书 PEM 路径 | `dialer/hysteria2.go:139-153` |
| `ech` | base64 ECHConfigList | `dialer/hysteria2.go:226-232` |
| `upmbps` / `downmbps` | Mbps，×1_000_000/8 → bytes/s；**可单独出现**；downmbps→MaxRx | `dialer/hysteria2.go:182-196` |
| `maxTx` / `maxRx` | 旧式原始字节/秒；**两者同时出现才生效**，且不覆盖 up/downmbps | `dialer/hysteria2.go:198-211` |
| `obfs` | `salamander`（需 `obfs-password`）｜`gecko`（拒绝）｜其它拒绝 | `dialer/hysteria2.go:212-222` |
| `cc_override` | 客户端本地 CC，allowlist：`bbr`/`brutal`/`bbr3`；`cubic`/`new_reno`/其它报错 | `client/congestion.go:28-40` |
| `#name` | 展示名 | `dialer/hysteria2.go:235` |

dae 另外把全局 `udphop_interval`（默认 30s，`dae/config/config.go:61`）经 `ExtraOption.UDPHopInterval`
传进 dialer（`dae/component/outbound/dialer/dialer.go:265`）——**链接语法里没有 interval 参数**。

## 2. 认证（HTTP/3）

客户端用 http3 库发一个 POST（`client/client.go:131-160`），服务端是任意 HTTP/3 handler：

```
请求：:method POST（QPACK 静态索引 20）
      :scheme https（23）
      :authority hysteria（name-ref 0 + literal 值）
      :path /auth（name-ref 1 + literal 值）
      hysteria-auth:    <auth>                     （internal/http.go:12）
      hysteria-cc-rx:   <MaxRx 十进制>              （internal/http.go:14,43）
      hysteria-padding: <256..2048 随机字母数字>     （internal/padding.go:50）
响应：:status == 233（AuthOK，internal/http.go:19）方可继续
      hysteria-udp: true|false                    （UDP 能力开关）
      hysteria-cc-rx: 数字 | `auto`               （服务端下行带宽/交给服务端测速）
      hysteria-padding: …（客户端忽略）
```

- QPACK：quic-go 的编码器对 literal 名字/值**总是 HPACK Huffman 编码**；客户端解码器必须实现
  Huffman（RFC 7541 附录 B 表）与 QPACK 的「literal name」H 位（RFC 9204：`001N Hxxx`）。
- 认证请求的 MaxRx = 链接的 downmbps/maxRx（0 = 让服务端测速）；`auto` 响应表示服务端会自行检测。
- 失败路径：状态非 233 → 返回 `AuthError{StatusCode}`（`hy2/errors`）；连接被关闭而不 panic。

## 3. TCP 代理（双向流）

每上游 TCP 连接开一条 QUIC 双向流（`internal/protocol/proxy.go`）：

```
请求（客户端→服务端，写一次）：
  FrameTypeTCPRequest = varint 0x401            （proxy.go:14；编码 44 01）
  AddressLength        = QUIC varint，1..2048    （proxy.go:18,43）
  Address              = "host:port" 字节
  PaddingLength        = QUIC varint（生成时 64..511，上限 4096）
  Padding              = 随机字节
  之后：裸字节流（与 TLS/ECH 无关，直接是 QUIC 流载荷）

响应（服务端→客户端，第一个非帧字节起）：
  Status     = 1 字节（0=OK，其它=错误）
  MsgLength  = QUIC varint（1..2048，error 时是错误文本）
  Msg        = 字节
  PaddingLength = QUIC varint（生成时 128..1023，上限 4096）
  Padding    = 随机字节
  之后：裸字节流
```

- 半关闭：QUIC FIN（`stream.Close/Finish`）；主动中止读：`STOP_SENDING(0)`。
- 拨号等待响应即 `connect_tcp` 返回；FastOpen（不等响应直接发数据）本实现不做。
- 长度上限：address 2048、message 2048、padding 4096（`proxy.go:18-20,43,100,55`）。

## 4. UDP 代理（QUIC DATAGRAM）

帧格式（`client/udp.go:268-289` + `internal/frag`）：

```
SessionID  u32 BE    每 NAT 会话一个，从 1 递增（udp.go:397,563-564）
PacketID   u16 BE    单包 = 0；分片 = rand(1..=0xffff)
FragID     u8        0-based 片号；单包 = 0
FragCount  u8        片数；单包 = 1
AddrLen    QUIC varint
Addr       "host:port" 字节（**每一片都带**）
Data       payload
```

- 发送：先试单包；`DatagramTooLargeError` 时按 `MaxDataLen` 预算分片（`udp.go:282-300`），
  片数上限由 u8 计数决定（≤255）。
- 接收：按会话内 `PacketID` 重组；同 `PacketID` 但 `FragCount` 变化 = 新一组；重复片丢弃；
  `FragID >= FragCount` 丢弃；一组收齐才投递；会话空闲/关闭即回收。
- 无会话关闭报文；会话由服务端按 `SessionID` 缓存 UDP socket。
- 服务端 → 客户端同样格式，`Addr` 是回包来源地址（客户端可据此做多目标）。

## 5. salamander 混淆（可选）

逐 wire datagram（`hy2/obfs/salamander.go`）：

```
out = salt(8B, 随机) || (payload XOR key)
key = BLAKE2b-256(PSK || salt)       32B，keystream 以 32B 循环
```

- PSK ≥ 4B（否则 `ErrPSKTooShort`）；收侧 `len <= 8` 丢弃（`salamander.go:56-63`）。
- 包装在 PacketConn 层：不是 OOBCapable 就失去 GSO/ECN 优化（`obfs/conn.go`）——每包一次写。
- gecko 未实现（`dialer/hysteria2.go:218-219` 直接报错）。

## 6. udphop（可选）

- 端口并集语法（`hy2/udphop/addr.go:120-180`）：逗号分隔单端口/范围；`all`/`*` = 全端口；
  归一化 = 排序 + 合并重叠。
- 连接策略（`hy2/udphop/conn.go:324-390`）：
  - 构造时建第一个 socket（新四元组），此后每 `HopInterval`（**最小 5s**，`conn.go:138-141`）
    随机挑一个目标端口，建**新 socket**（新随机本地端口）；
  - 旧 socket 保留一个间隔（`prevConn` 宽限，期间两个 socket 都收）；
  - 读取端屏蔽具体来源，对 QUIC 层谎报逻辑服务器地址；
  - 写端忽略 quic-go 给的目的地，发往当前跳。
- 服务端：quic-go fork 对每个有效包更新客户端 remote addr（`quic/connection.go:924-929`
  “Hysteria connection migration”），因此无需服务端配置；但服务端部署需让整个端口范围可达
  （端口转发/NAT 到同一进程）。

## 7. 拥塞控制（客户端本地）

- 认证成功后按 `resolveCongestion` 决策（`client/congestion.go:72-107`）：
  - override 空：服务端回 `auto` → 默认 CC（fork 默认 bbr3）；否则
    `min(server_rx, client_tx)` > 0 → **Brutal**，速率 = 该值；
  - `bbr` → BBR；`bbr3` → bbr3；`brutal` → 同 min() 计算，无带宽信息时回退 BBR；
  - Brutal 语义：固定目标速率、窗口 ≈ 2×BDP、丢包不降速（`protocol/tuic/congestion`）。
- 线上没有 CC 协商字段；`Hysteria-CC-RX` 只上报客户端下行带宽声明。

## 8. 本仓库（mini-dae / Rust）的对应实现与边界

| 项 | Rust 实现 | 与 Go 的差异（如实） |
|---|---|---|
| 认证 | `hysteria2.rs` + `hpack.rs`（手写 QPACK 编码、HPACK Huffman 解码） | QPACK 只用静态表/字面量；动态表引用报错 |
| TCP/UDP | `hysteria2.rs` 帧编解码与 quinn 流/datagram | 拨号期读响应（非 FastOpen） |
| salamander | `quicsock::ObfsSocket`（blake2 0.10） | 同样关闭 GSO；`gecko` 拒绝 |
| Brutal | `brutal.rs` HybridController：`window=max(2mtu, rate×srtt)`、丢包不收缩 | **近似**：无 pacer 直接控制，quinn pacer 使速率约 +25%；无 ackRate 反馈 |
| bbr3 | 映射到 quinn BBR v1 | 近似，非真 bbr3 |
| udphop | `quicsock::HopSocket`（谎报地址 + 跳时唤醒 driver） | 间隔可用链接扩展 `udphop-interval`（dae 放全局配置）；Go 用 ticker，本实现由发包驱动 |
| pinSHA256/ECH/custom CA | 未做（配置期报错） | 见 ADR-0019/0020 |

参考实现对照：Go 参考服务端 `lab/proto-check/hy2-server`（http3 + StreamHijacker + datagram 循环，
obfs 与多端口 mux 用 outbound 的 `obfs`/`udphop` 包），Rust 侧跨实现测试与其对拍（见 ADR-0019/0020 的验证章节）。
