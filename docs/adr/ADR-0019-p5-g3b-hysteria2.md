# ADR-0019：P5 G3b 执行——hysteria2（QUIC + 最小 HTTP/3 认证）

- **状态**：已采纳（2026-10-03）
- **对应**：ADR-0018 第 6 条（G3b 的范围与路径）；ADR-0004 的协议梯度第三梯（QUIC 系）
- **相关**：ADR-0018（G3a：tuic v5 引入 QUIC 运行时/tokio 桥接）、ADR-0016/0017（验收口径：独立对端 + 协议/offload 互斥）

## 背景

ADR-0018 已把 hysteria2 的范围定清楚，本轮按该范围执行。实现前从 Go 侧源码核对的关键事实：

1. **认证是标准 HTTP/3 请求**：control 单向流 `[0x00][SETTINGS 0x04 0x00]`（需保持打开）+ 一条双向流发
   HEADERS 帧（`0x01 | len varint | QPACK 块`）+ FIN；成功状态是 **`:status == 233`**（不是 200）；
   `Hysteria-UDP` / `Hysteria-CC-RX` 从响应头读。
2. **QPACK 解码必须支持 HPACK Huffman**：quic-go 对 literal 的 name/value 总是 Huffman 编码（包括
   不在静态表里的 `hysteria-*` 名字）。本机 cargo 缓存没有 hpack 类 crate（`cargo search` 网络不稳），
   表从本机 Go module 缓存机械提取生成：`lab/gen-huffman-table.py` → `loader/src/huffman_table.rs`
   （HPACK 表来自 `golang.org/x/net/http2/hpack`，即 RFC 7541 附录 B；QPACK 静态表来自 `olicesx/qpack`）。
3. **HTTP/3 层的 `H3_DATAGRAM` 不能声明**（服务端 `EnableDatagrams: false`，只开 QUIC 层 datagram）：
   quic-go fork 的 http3 客户端一看到 `H3_DATAGRAM` 就启动 receiveDatagrams 循环，把 UDP relay 的
   裸 QUIC datagram 吃掉。真实 hysteria2 服务端同理。
4. **代理帧**：TCP 请求 `0x401（varint 44 01）| addr_len | "host:port" | pad_len | padding(64..511)`，
   之后裸字节；响应 `status(0=ok/1=err) | msg_len | msg | pad_len | padding`。UDP 走 QUIC datagram：
   `[SessionID u32][PacketID u16][FragID u8][FragCount u8][varint addr][data]`，服务端按 1200 字节
   预算分片回包（每片都带地址）。
5. **两个不能照抄的难度点**：Brutal 拥塞控制在 quinn 的 `Controller`（窗口/事件粒度）下只能近似；
   salamander 混淆需要包 `quinn::AsyncUdpSocket` 并处理 GSO 段。

## 决策

1. **hysteria2 客户端子集**（`loader/src/hysteria2.rs` + `hpack.rs` + `huffman_table.rs`）：
   - QUIC：ALPN 缺省 `h3`；keepalive 5s / idle 60s；datagram 双向显式开启（收/发缓冲各 1MB）；
   - 认证：control 流保持打开；请求头 `:method POST`/`:scheme https`/`:authority hysteria`/`:path /auth` +
     `hysteria-auth`/`hysteria-cc-rx`（downmbps/maxRx → 字节/秒，0 = 让服务端测速）/`hysteria-padding`
     （256..2048 随机字母数字）；校验 `:status == 233`、读 `Hysteria-UDP`；失败返回错误（不 panic）；
   - TCP：每条 relay 连接一条双向流；请求帧后裸字节；**拨号阶段读响应**（非 FastOpen，便于错误上报）；
     半关闭 = QUIC FIN；
   - UDP：`[SessionID u32]`（每 NAT 会话一个，从 1 递增）；单包 `PacketID=0/FragID=0/FragCount=1`；
     超预算按 1200/1452 分片（随机 PacketID，每片带地址）；接收按单候选重组（PacketID/FragCount
     变更即重置、重复片丢弃、越界片丢弃、30s 过期）；
   - 连接策略：一个 dialer 复用一条 QUIC 连接（与 tuic 同构；`close_reason()` 非空时下次拨号重建）。
2. **链接参数**（`hysteria2://` 与别名 `hy2://`）：auth = userinfo（`user:pass` 分别解码后拼回）；
   `sni`（空回退主机名）、`insecure`（Go `strconv.ParseBool` 接受集合）、`upmbps`/`downmbps`
   （Mbps × 1_000_000 / 8；downmbps → MaxRx → `Hysteria-CC-RX`）、`maxTx`/`maxRx`（仅两者同时出现时
   生效，且不覆盖 upmbps/downmbps 已给出的维度）、`cc_override` 接受但不参与（本地 CC 选择，无线上语义）。
3. **明确不做（本轮边界，如实标注）**：
   - **Brutal 拥塞控制**：用 quinn 自带 CC（不影响互通，只影响速率控制风格）；
   - **salamander / gecko 混淆**：链接出现 `obfs=` 即配置期报错；
   - `pinSHA256` / `ech` / 自定义 `ca`：配置期报错（需要证书回调/自定义根，tls 层暂无入口）；
   - udphop、0-RTT、连接迁移。
4. **Go 参考服务端**（`lab/proto-check/hy2-server/`，独立实现，不复用 outbound 代码）：
   `http3.Server` + `StreamHijacker` 截获 0x401、`/auth` 校验 `Hysteria-Auth` 回 233 +
   `Hysteria-UDP: true`、QUIC datagram 循环 + 1200 预算分片回包、上游 TCP/UDP best-effort SO_MARK
   （非 root EPERM 降级告警）。
5. **UDP 出口复用**：新增 `UdpKind::Hy2`（与 `UdpKind::Tuic` 同形），`supports_udp()` 纳入
   hysteria2；`supports_offload()` 保持 false（QUIC 无底层 TcpStream）。
6. **验收口径**（同 G3a）：本地跨实现单测 + lab e2e（含 offload 互斥与状态面断言）+ 全量回归。

## 理由

- h3 认证是 hysteria2 与 tuic 的本质差异，QPACK/HPACK 是硬门槛：把表生成与码流编解码做成**可单测的
  纯函数**（RFC 7541 官方向量校验），再接到 QUIC 层，认证失败（协议层）与传输失败（QUIC 层）能分开定位；
- 参考服务端用 http3 + StreamHijacker 是 Go 侧可达的最小结构，能覆盖真实 quic-go 行为（Huffman
  literal、datagram 能力协商、`DatagramTooLargeError` 分片），比自写 QPACK 服务端更有交叉验证价值；
- 不做 Brutal/salamander 是范围决策：它们在 quinn 下不是「多写一点」，而是各要一层（拥塞控制近似 /
  包级编解码 + GSO 段处理），首版先用互通与转发正确性验收，能力缺什么在报错与文档里说清楚。

## 后果

- 正面：`--dialer` 梯度到 `…|tuic://|hysteria2://`；HPACK Huffman/QPACK 成为仓库内共享件；
  QUIC 运行时被第二条协议验证（连接复用、datagram、流半关闭路径）。
- 负面/代价：无混淆 = 流量特征与官方客户端不同；无 Brutal = 高延迟链路下的吞吐策略不同；
  认证失败只有 status 码，无更细原因（对照 Go 侧同）。
- 风险：QPACK 解码只支持静态表（我们发出与服务的响应都只用静态表；若未来服务端启用动态表，需扩解码器）；
  响应头 `hysteria-cc-rx: auto` 被忽略（quinn 自带 CC 下无意义）。

## 验证方式（实测）

- `cargo test --release`：64/64（比 G3a 的 53 多 11 项：hysteria2 varint/帧/重组 4、HPACK Huffman/QPACK 5、
  跨实现 TCP/UDP 2）。
- 跨实现单测：Rust/quinn ↔ Go/http3 参考服务端（TCP 256KB 往返 + FIN 透传；UDP 小包 + 3000B 强制分片）。
- `lab.sh hy2-up && test-hy2`：`stream-ok bytes=524288`；
  `hy2 tcp: conns=2 bytes_up=524299 bytes_down=524333 offloaded=0`；Go 服务端日志 `TCP target=1.1.1.1:8080`。
- `lab.sh hy2-udp-up && test-hy2-udp`：`summary=3/3`；`hy2 udp: sessions=1/1 proxied=1 fallback=0`；
  服务端日志 `UDP target=2.2.2.2:9998`。
- 回归：标准/单臂 verify 9/9；DNS 六专项；relay/offload/UDP 五专项；G1/G2/G3a 专项；
  proto-check（真实 Go 客户端 ↔ Python 服务端）；`lab/parity.sh` 逐字节一致。

## 修订条件

Brutal 近似移植、salamander/gecko 混淆、udphop、`pinSHA256`/`ech`/`ca`、QPACK 动态表中任一落地时，
新写 ADR 取代对应子条并互链；若出现成熟的 h3 客户端库可替换手写 QPACK，另写 ADR 评估。
