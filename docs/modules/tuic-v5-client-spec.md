# TUIC v5 客户端字节级协议规格

> 研究对象：`github.com/olicesx/outbound@v0.0.0-sticky-ip.0.20260918090140-cc86ced2e683`（dae 使用的 outbound 分支）。
> 用途：Rust（quinn 0.11）重写客户端 + Go（quic-go）独立参考服务端交叉验证。
> 证据等级：**源码实测**（阅读源码得出）｜**测试实测**（仓库自带测试的行为）｜**推断**（未验证）。
> 路径缩写：
> - `tuic/` = `protocol/tuic/`
> - `dialer/tuic/` = `dialer/tuic/`
> - `common/` = `protocol/tuic/common/`
> - `quic/` = `github.com/olicesx/quic-go@v0.0.0-20260910141758-62d80bbebb5b/`
> - 本文所有 `文件:行号` 都相对上述缩写。

## 0. 总览

| 命令 | 值 | 承载 | 状态 |
|---|---|---|---|
| Authenticate | `0x00` | 客户端单向流（一连接一次） | `tuic/protocol.go:31` |
| Connect | `0x01` | 客户端双向流（每 TCP 连接一条） | `tuic/protocol.go:32` |
| Packet | `0x02` | QUIC DATAGRAM（native）或单向流（quic relay） | `tuic/protocol.go:33` |
| Dissociate | `0x03` | 客户端单向流（关闭 UDP 关联） | `tuic/protocol.go:34` |
| Heartbeat | `0x04` | DATAGRAM（本实现只收不发） | `tuic/protocol.go:35` |

版本号恒为 `0x05`（`Ver5`，`tuic/client.go:24`），每个命令首字节携带。
ATYP：`0=域名`、`1=IPv4`、`2=IPv6`、`255/0xff=None`（仅用于非首分片）——`tuic/protocol.go:453-458`。
应用错误码：`ProtocolError=0xfffffff0`、`AuthenticationFailed=0xfffffff1`、`AuthenticationTimeout=0xfffffff2`、`BadCommand=0xfffffff3`——`tuic/protocol.go:645-650`（e2e 服务端同值，`tuic/e2e_test.go:159-163`）。

## 1. 链接 / 配置

解析入口 `dialer/tuic/tuic.go:92-135`（`ParseTuicURL`），链接形如：

```
tuic://<uuid>:<password>@host:port?allow_insecure=1&sni=...&alpn=h3&congestion_control=bbr&udp_relay_mode=native[&cwnd=...&cc_override=...]
```

| 参数 | 含义与默认 | 来源 |
|---|---|---|
| URL user | UUID 字符串，`uuid.Parse` 失败直接报错 | `tuic/dialer.go:34-37` |
| URL password | 密码原文（UTF-8 字节） | `dialer/tuic/tuic.go:117` |
| `sni` | 取值顺序 `peer` > `sni` > 链接主机名 | `dialer/linkparams.go:242-250` |
| `disable_sni` | `true` 时 `sni=""` 且强制 `allowInsecure=true` | `dialer/tuic/tuic.go:108-112` |
| `alpn` | 逗号分隔并 trim；**本仓库没有默认值**，缺省即不提供 ALPN | `dialer/tuic/tuic.go:99-105, 72` |
| `allowInsecure` | 接受 4 种拼写：`allowInsecure`/`allow_insecure`/`allowinsecure`/`skipVerify`；另可被全局 `ExtraOption.AllowInsecure` 置位 | `dialer/linkparams.go:228-237`、`dialer/tuic/tuic.go:75` |
| `congestion_control` | 原样透传，仅参与本地 CC 选择（TUIC v5 线上**没有** CC 协商） | `dialer/tuic/tuic.go:66,127` |
| `cc_override` | 客户端本地覆盖，allowlist：`bbr`/`cubic`/`new_reno`/`brutal`/`bbr3`，非法值报错 | `common/congestion.go:42-48, 79-90` |
| `cwnd` | 非负整数，`brutal` 的目标速率（bytes/s） | `dialer/linkparams.go:255-261` |
| `udp_relay_mode` | `quic` 置 flag；其它值（含缺省/`native`）为 native。**dae 在 dialer 层硬钉死 NATIVE** | `dialer/tuic/tuic.go:130,61-63`、`tuic/dialer.go:40-44` |

固定项：TLS `MinVersion=1.3`（`dialer/tuic/tuic.go:73`）。`tuic/tuic.go:5-7` 定义了 `DefaultTCPTimeout/DefaultUDPTimeout = 5s`，但协议路径中**未被使用**（源码实测）。

### token 的确切算法

`GenToken`（`tuic/protocol.go:148-156`）：

```
token[32] = TLS.ExportKeyingMaterial(label = UUID 的 16 个原始字节, context = password 的 UTF-8 字节, length = 32)
```

- **不是** `sha256(password)`、**不是** HMAC、**不是** 明文比较；它是 TLS 1.3 keying material exporter（RFC 5705/8446 语义），随会话密钥变化，离线无法计算。
- label 是 16 字节裸 UUID（Go `string(uuid[:])`），不是 UUID 字符串（`tuic/protocol.go:150`）。
- 服务端用同样参数对 `conn.ConnectionState().TLS` 求值后逐字节比较（参考实现：`tuic/e2e_test.go:443-454`）。
- quinn/rustls 对应 `Connection::export_keying_material(label, context, len)`，注意必须在 TLS 握手完成后调用。

## 2. QUIC 层与握手

### 2.1 客户端 QUIC 配置（源码实测）

| 项 | 值 | 来源 |
|---|---|---|
| QUIC 版本 | v1（quic-go 默认） | — |
| TLS | 1.3 only | `dialer/tuic/tuic.go:73` |
| ALPN | 由链接决定；e2e 用 `h3`。外部 TUIC 生态惯例为 `h3`（**推断**，本仓库无默认） | `tuic/e2e_test.go:352` |
| KeepAlivePeriod | **3s** | `tuic/dialer.go:71` |
| HandshakeIdleTimeout | **8s** | `tuic/dialer.go:74` |
| MaxIdleTimeout | 未设置 → quic-go 默认 30s | `quic/internal/protocol/params.go:100` |
| EnableDatagrams | true | `tuic/dialer.go:73` |
| DisablePathMTUDiscovery | false（开启 DPLPMTUD） | `tuic/dialer.go:72` |
| 流/连接接收窗口 | stream 初 8MiB / 上限 32MiB；conn 初 12MiB / 上限 64MiB | `common/congestion.go:11-16` |
| 0-RTT | 调用 `DialEarly`（`ReduceRtt=true`），但未配置 `ClientSessionCache`，实际拿不到 ticket，等效 1-RTT（**推断**：源码无 session cache 配置） | `tuic/client.go:166-170`、`tuic/dialer.go:81` |
| 建连 | 一个 clientImpl 复用一个 QUIC 连接；首个业务请求触发建连并认证 | `tuic/client.go:148-198` |

### 2.2 握手：Authenticate（第一条流）

客户端在 TLS 完成后**立即自主打开一条单向流（unidirectional）**，写入 50 字节后 FIN（`tuic/client.go:200-227`）：

| 偏移 | 字段 | 长度 | 值 |
|---|---|---|---|
| 0 | VER | 1 | `0x05` |
| 1 | TYPE | 1 | `0x00` |
| 2 | UUID | 16 | 原始 16 字节，无任何编码/字符串化 |
| 18 | TOKEN | 32 | §1 的 exporter 结果 |

序列化实现：`tuic/protocol.go:158-176`；发送顺序：`OpenUniStream → write → stream.Close()`（`tuic/client.go:204-225`）。

### 2.3 响应与失败语义

- **成功时服务端不发送任何响应**（v5 没有认证响应帧/状态字）。参考服务端只在失败时动作（`tuic/e2e_test.go:443-454`：验证通过仅 `close(authOK)`）。
- 失败：服务端 `CloseWithError(AuthenticationFailed=0xfffffff1, "invalid credentials")`，参考：`tuic/e2e_test.go:450`；客户端不会在认证流上读到错误，而是在后续 dial/read/write 时以 QUIC 连接级 ApplicationError 暴露（`tuic/e2e_test.go:845-890`）。
- 服务端可选认证超时：e2e 参考为 10s，超时用 `0xfffffff2`（`tuic/e2e_test.go:500-502, 572-574`）。
- 版本/命令非法：`0xfffffff3`（`tuic/e2e_test.go:428, 464, 487, 551, 560`）。
- 客户端在收到认证成功前不会等待；它信任连接继续可用（无 ack）。
- 客户端**从不在 QUIC 连接上 accept 服务端发起的双向流**（源码实测：无 `AcceptStream` 调用）；服务端→客户端数据只能走 DATAGRAM、客户端自己开的流的回程、或 relay 模式下服务端开的单向流。

## 3. TCP 转发

- 每条 TCP 连接 = **新开一条 QUIC 双向流**（`quicConn.OpenStream()`，`tuic/client.go:573`），多个 TCP 复用同一条 QUIC 连接。
- 流首部：`Connect` 命令 + 目标地址，**没有长度字段、没有分片字段**（`tuic/client.go:566-569`、`tuic/protocol.go:178-232`）：

| 偏移 | 字段 | 长度 |
|---|---|---|
| 0 | VER=`0x05` | 1 |
| 1 | TYPE=`0x01` | 1 |
| 2 | ATYP | 1（0/1/2） |
| 3.. | ADDR | IPv4 4B / IPv6 16B / 域名 `len(1)+name` |
| 末尾 | PORT | 2B，大端 |

- 首部之后即**纯裸字节**，直到 FIN（双向都如此）。
- **没有 CONNECT 响应/状态字**。目标不可达时 v5 无法在 dial 阶段报错；参考服务端做法是 `CancelRead(0)+CancelWrite(0)` 直接杀死该流（`tuic/e2e_test.go:504-511`），客户端把它表现为后续读写错误。
- 半关闭：`CloseWrite()` = QUIC `stream.Close()` = FIN，仅关闭发送方向（`common/stream.go:75-84`）；对端 FIN 以 `io.EOF` 呈现，服务端应把 FIN 透传为目标 TCP 的 `CloseWrite`（`tuic/e2e_test.go:513-527`）。
- 全关闭：`SetWriteDeadline(now)` → `CancelRead(0)`（STOP_SENDING, code 0）→ FIN（`common/stream.go:86-103`）。
- 单流错误（reset 等）不会杀死共享隧道；只有非临时错误才触发连接级关闭（`tuic/client.go:441-462`）。

## 4. UDP 转发

### 4.1 承载方式

- **native（dae 唯一使用）**：QUIC DATAGRAM（RFC 9221），一条 datagram 恰好装一个 Packet 命令（`tuic/packet.go:802-807`）。
- **quic relay（可选，生态兼容）**：每个 Packet 命令开一条客户端单向流（`tuic/packet.go:787-801`）。
- 接收端两种情况都解析：native 走 `ReceiveDatagram`（`tuic/client.go:288-315`），relay 走 `AcceptUniStream`（`tuic/client.go:229-286`）。

### 4.2 Packet 帧布局（大端）

| 偏移 | 字段 | 长度 | 说明 |
|---|---|---|---|
| 0 | VER | 1 | `0x05` |
| 1 | TYPE | 1 | `0x02` |
| 2 | ASSOC_ID | 2 | 客户端随机分配 |
| 4 | PKT_ID | 2 | 同一 UDP 报文的各分片相同；无分片时对端可忽略 |
| 6 | FRAG_TOTAL | 1 | 总片数；不分片 = 1 |
| 7 | FRAG_ID | 1 | 本片序号，0 起 |
| 8 | SIZE | 2 | 本片 **DATA 的字节数**（不是总长） |
| 10 | ADDR | 变长 | ATYP + 地址 + 端口；非首片仅 1 字节 `0xff` |
| … | DATA | SIZE | 本片负载 |

字段顺序与序列化：`tuic/protocol.go:238-370`；解析参考：`tuic/packet_parse.go:41-146`、服务端视角 `tuic/e2e_test.go:226-290`。

### 4.3 分片规则

- 触发条件：直接 `SendDatagram` 返回 `DatagramTooLargeError`（`tuic/packet.go:808-816`）。
- 分片尺寸：`fragSize = MaxDataLen(由错误给出) - 首片头长度`，再以 `MaxUdpRelayPacketSize=1452` 封顶（`tuic/dialer.go:39,83`、`tuic/packet.go:810-814`）。
- 片数上限 255（`FRAG_TOTAL` 为 uint8，`tuic/frag.go:22-25`）。
- 首片（FRAG_ID=0）带完整地址；其余片 `ATYP=0xff`，**不写地址和端口**（`tuic/frag.go:32-44`，序列化 1 字节：`tuic/protocol.go:595-605`）。
- 每片独立携带相同的 ASSOC_ID/PKT_ID/FRAG_TOTAL 和自己的 FRAG_ID/SIZE/DATA（`tuic/frag.go:42-47`）。

### 4.4 重组窗口（客户端侧，服务端发回包时须匹配）

- 按 ASSOC_ID 分流到关联队列；按 PKT_ID 建 bucket（16 位会复用，bucket 内可并存多个 deFragger，用 `FRAG_TOTAL`、槽位占用、首片地址区分）——`tuic/packet.go:637-643`、`tuic/frag.go:122-143`。
- 必须集齐所有 `FRAG_ID` 槽位**且收到 FRAG_ID=0 且首片带合法地址**才投递；总长 = 各片 DATA 实际长度之和（`tuic/frag.go:145-147,173-192`）。
- 重复片丢弃；`FRAG_ID >= FRAG_TOTAL` 丢弃；同一 PKT_ID 多候选且非首片无法消歧时丢弃（`tuic/packet.go:431-448`、`tuic/frag.go:157-160,183-185`）。
- 空闲 30s 过期、清理节流 5s（`tuic/packet.go:298-300, 538-557`）。
- 无分片（FRAG_TOTAL ≤ 1，含 0）按整包直接投递（`tuic/packet.go:625-634, 697-713`）。
- `ReadFrom` 的缓冲区若小于重组总长，会重组到临时缓冲并**截断返回**（`tuic/packet.go:650-662`）；Rust 实现应要求足够大的缓冲或显式报错。

### 4.5 UDP 关联生命周期

- ASSOC_ID 由客户端随机选取 `[0, 65534]`（`fastrand.Intn(0xFFFF)`），保证同一 QUIC 连接内不冲突；无创建握手，服务端在首个 Packet 处懒建关联（`tuic/client.go:619-627`，服务端参考 `tuic/e2e_test.go:576-595`）。
- 回包必须携带相同 ASSOC_ID；客户端按 ID 严格分流，未知 ID 静默丢弃（`tuic/client.go:367-376`）。
- 客户端关闭关联：在**新单向流**上发 `Dissociate` = `05 03 ASSOC_ID(2B BE)`，共 4 字节，然后从 map 删除（`tuic/packet.go:504-525`、`tuic/protocol.go:374-422`）。若隧道已死则不发（`client.go` 的 `forceClose` 语义）。
- 客户端侧没有关联空闲超时（只有应用 `SetDeadline`；写 deadline 触发即整条关联关闭，`tuic/packet.go:875-877`）。
- 服务端回包中的地址应为**目标 UDP 的真实源地址**（客户端把它作为 `ReadFrom` 的 addr 返回；e2e 参考 `tuic/e2e_test.go:292-311`）。

## 5. 心跳 / 保活 / 迁移 / 拥塞控制 / 报文尺寸

- **保活**：QUIC 层 `KeepAlivePeriod=3s`（`tuic/dialer.go:71`），空闲上限默认 30s。
- **心跳命令**：定义了 `Heartbeat(0x04)`（2 字节），但本客户端**从不发送**；收到 datagram 心跳只忽略（`tuic/client.go:377-379`）。服务端参考同样只接受不回应（`tuic/e2e_test.go:555-557`）。参考服务端必须容忍“无心跳”。
- **迁移**：协议层无任何迁移逻辑；依赖 quic-go 的连接迁移 + 路径 MTU 发现（`DisablePathMTUDiscovery=false`）。客户端对 UDP socket 使用 FakeNetPacketConn 的假本地地址（dae 路由需要，`tuic/dialer.go:99-107`、`common/unique_addr.go:134-145`），与互通无关。
- **拥塞控制**：线上无协商。默认值看具体实现：dae 分支在外部均无 `cc_override`、服务端未“回显 brutal+速率”时用 **`bbr3`**（fork 私有，默认值 `common/congestion.go:53`）；`brutal` 仅在配置声明且 `cwnd>0` 时启用（`common/congestion.go:79-90, 98-117`）。标准 TUIC 服务端无需感知，客户端 CC 纯本地。
- **DATAGRAM 最大尺寸**：
  - 协商 = QUIC 传输参数 `max_datagram_frame_size`。本 fork 一旦 `EnableDatagrams=true` 就广播 **16383**（`quic/internal/wire/datagram_frame.go:14`、`quic/connection.go:314,423`）。
  - 单次可发上限 = `min(对端参数, 本地路径 MTU 估算)`，超出返回 `DatagramTooLargeError`（本 fork 字段 `MaxDataLen`；上游 quic-go 字段名 `MaxDatagramPayloadSize`）——`quic/connection.go:2534-2542`。
  - 应用层再对分片负载封顶 1452（= `MaxPacketBufferSize`，`quic/internal/protocol/protocol.go:111`）。
  - 上游 quic-go（v0.63.0，pkg.go.dev 查证）同样只需 `EnableDatagrams: true`，Config 无 `MaxDatagramFrameSize` 字段；**Rust/quinn 侧用 `max_datagram_size()` 取当前上限**，不要硬编码。

## 6. 实现要点与边界条件（测试提炼）

1. **空/短 datagram**：`<2` 字节（连命令头都不全）计一次 malformed 后丢弃；`<10` 字节或任何字段截断同样 malformed（`tuic/client.go:328-341`、`tuic/packet_parse.go:41-146`、测试 `tuic/client_malformed_datagram_test.go:31-52`）。
2. **malformed 升级阈值**：单包丢弃不杀隧道；窗口内累计 **4096** 次 malformed → forceClose 整条隧道并复位窗口；日志限频 5s（`tuic/client.go:382-438`）。
3. **未知命令类型**：datagram 中 TYPE 既非 2 也非 4 → 静默忽略，不计 malformed（测试 `client_malformed_datagram_test.go:54-68`）。
4. **未知/已关闭 ASSOC_ID**：回包直接释放丢弃，不报错（`tuic/client.go:367-376, 322-326`）。
5. **分片异常**：重复片、越界 FRAG_ID、首片缺地址（AtypNone）、无法消歧的非首片——全部丢弃；30s 后随桶过期（见 §4.4）。
6. **队列背压**：每关联 2048 包上限，满则丢弃并计数，绝不阻塞解复用 goroutine（`tuic/packet.go:22-26, 107-122`、测试 `packet_pushback_test.go:11-35`）。
7. **relay 单向流**：流超 30s 未读完 → 取消该流、释放并发槽（64 个），隧道存活；流上出现非 Packet 命令 → 视为协议违规，forceClose 隧道（`tuic/client.go:26-30, 229-286`）。
8. **TCP 流提前关闭**：`*quic.StreamError` 被视为单流错误不上报隧道（`tuic/client.go:441-445`）；流耗尽（`StreamLimitReachedError`）按单次失败回退（`tuic/client.go:453-460`）。
9. **隧道退休**：`forceClose` 立即对写侧失败，但 QUIC 连接与底层 socket 保留 **10s** 宽限期后才 `CloseWithError(0xfffffff0)`（`tuic/client.go:464-521`）。
10. **版本字节**：客户端接收路径**不校验** VER（解析只读不用，`tuic/packet_parse.go:50`）；服务端应始终发 `0x05`。
11. **0 长负载**：SIZE=0、DATA 为空合法；不分片时原样投递 0 长报文（`tuic/packet_parse.go:71-80`、`tuic/packet.go:625-634`）。
12. Datagram 发送队列满：quic-go fork 等待 30s 后返回 `ErrDatagramQueueFullTimeout`，该错误被视为临时错误、不退休隧道（`quic/datagram_queue.go:48-53`、`tuic/client_test.go`/`client_lifecycle_test.go:51-85`）。

## 7. Go 参考服务端（quic-go）互通检查单

1. `quic.ListenAddr`：`tls.Config{Certificates, NextProtos: []string{"h3"}`, `MinVersion: TLS13}`；`quic.Config{EnableDatagrams: true, Allow0RTT: true, MaxIdleTimeout: 30s}`。上游 quic-go 无需也不应设置已不存在的 `MaxDatagramFrameSize`（v0.63 已查证仅 `EnableDatagrams`；本 fork 同样）。参考实现见 `tuic/e2e_test.go:348-381`。
2. 每连接并发启动：uni stream 循环、bidi stream 循环、datagram 循环（`tuic/e2e_test.go:397-405`）。
3. Uni stream：读 `VER+TYPE`。TYPE=0：读 16B UUID + 32B TOKEN，用 `conn.ConnectionState().TLS.ExportKeyingMaterial(string(uuidBytes[:]), []byte(password), 32)` 比对；失败 `CloseWithError(0xfffffff1)`，成功**不回包**；只认第一条认证（`authOnce`）。版本非 5 → `0xfffffff3`（`tuic/e2e_test.go:420-454`）。
4. 认证前不得转发任何 CONNECT/Packet；可设 10s 认证超时 → `0xfffffff2`（`tuic/e2e_test.go:495-503, 568-575`）。
5. CONNECT（bidi stream）：VER=5、TYPE=1、读地址；拨号失败就 `CancelRead(0)+CancelWrite(0)`（**没有状态帧**）；成功后双向 `io.Copy`，客户端 FIN → 目标 `CloseWrite`，目标 EOF → `stream.Close()`（`tuic/e2e_test.go:479-528`）。
6. Datagram 路径：TYPE=4 直接忽略；TYPE=2 解析并校验（`tuic/e2e_test.go:546-567`）。
7. ASSOC_ID：服务端按首个 Packet 懒建关联（`sync.Map` + 每关联一个 UDP socket）；首个包即转发；无需任何创建应答（`tuic/e2e_test.go:576-602`）。
8. 回包：Packet 帧使用相同 ASSOC_ID，ADDR 填**UDP 真实源地址**，PKT_ID 可自增（不分片时客户端忽略）；大回包 > `max_datagram_size` 时按 §4.3 规则分片（首片带地址，后续 `0xff`），否则客户端无法收到（`tuic/e2e_test.go:292-334`）。
9. Uni stream TYPE=3（Dissociate）：读 2 字节 ASSOC_ID，关闭并删除关联 socket（`tuic/e2e_test.go:455-462`）。
10. 支持 relay 模式兼容：在客户端单向流上读取“恰好一个 Packet 命令”（`tuic/packet_parse.go:148-196`），以供 `udp_relay_mode=quic` 的标准客户端使用；native 客户端不会发这种流。
11. 心跳：接受 TYPE=4 且可不应答；客户端不发也应正常。
12. 服务端可对关联设空闲回收（**源码未规定**；dae 客户端无超时，参考 e2e 服务端也不回收——长稳场景建议自行加 60s 级空闲清理，标记为推断性建议）。
13. 应用错误码与客户端一致（§0 表），便于交叉验证。

## 8. Rust/quinn 0.11 映射速查（推断，需以 quinn 文档核对）

| 需求 | quinn 对应 |
|---|---|
| token | `Connection::export_keying_material(&mut buf, label, context)`（必须握手完成后） |
| 认证/关联命令 | `open_uni()` → `write_all` → `finish()` |
| TCP | `open_bi()`；半关闭 `SendStream::finish()`；中止 `reset(code)` / `stop_sending(code)` |
| UDP | `send_datagram()` / `read_datagram()`；上限 `max_datagram_size()`；`SendDatagramError::TooLarge` 后自行分片 |
| Keepalive / idle | `TransportConfig::keep_alive_interval(Some(3s))`、`max_idle_timeout(...)` |
| 流控窗口 | `TransportConfig` 的 stream/connection receive window 系列 |
| ALPN | rustls `ClientConfig::alpn_protocols`（建议 `h3`） |

## 待验证清单

- ALPN `h3` 是外部生态惯例，本仓库无默认值；出网互通时需显式配置（**推断**）。
- 0-RTT 实际不会触发（无 `ClientSessionCache`），Rust 侧同样只有在配置 resumption store 后才有意义（**推断**）。
- `congestion_control` 仅在 dae 内部用于选 CC，无线上语义；与标准 TUIC 生态一致（**源码实测 + 推断**）。
