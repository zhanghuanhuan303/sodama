# ADR-0050：P26 HTTP/3 双项——DoH over H3 + `naive+quic://`（h3 CONNECT）

- **状态**：已采纳（2026-10-04）
- **对应**：对标表缺口 #5 的 DoH H3、以及 #6 P25 遗留的 naive H3 形态
- **相关**：ADR-0049（P25 h2 CONNECT）、ADR-0040/0047（DoH/DoQ 上游）、
  NOTES §11.41；对照 RFC 9114（HTTP/3）、RFC 9000 §16（varint）、
  hysteria2 既有最小 HTTP/3 认证（ADR-0019）

## 背景

- P25 后残留两处与 HTTP/3 相关的显式占位：DNS 上游 `h3://` 报「尚未实现」、
  `naive+quic://` 报「未实现」。
- 但所需部件都在：quinn 0.11 客户端栈（tuic/hy2/DoQ 已在用）、hy2 认证手写的
  「控制流 + SETTINGS + HEADERS/QPACK」最小 h3 交互、`hpack::qpack_encode/decode`。
- lab 侧 quic-go fork（`github.com/olicesx/quic-go`，dae 依赖树内）自带 `http3`
  服务端且支持 CONNECT（`http_stream.go`/`request_writer.go`），可在 `dae-work`
  模块图里离线构建夹具。

## 决策

1. **新模块 `h3client.rs`（最小 HTTP/3 客户端，h2client 对称）**：
   - `H3Conn::new(conn, ep)`：开控制流（type 0x00）+ 空 SETTINGS（保持打开）；
     `H3Shared` 同时持有控制流与 endpoint 句柄（隧道两半活着期间连接不被回收）；
   - `request()`：HEADERS + QPACK（伪头 + 自定义头）+ DATA(body) + FIN，收 HEADERS 取
     `:status`、收 DATA 累计 body（上限 256KB），读到流 FIN 结束——DoH 用；
   - `connect_tunnel()`：`:method`=CONNECT + `:authority`（无 `:scheme`/`:path`，
     RFC 9114 §4.4），2xx 后返回 `(H3TunnelReader, H3TunnelWriter)`——隧道数据走
     **DATA 帧**（RFC 9114 §4.4 明确），QUIC 自身负责流控；
   - `H3TunnelWriter`：每次写入切 ≤16KB DATA 帧；`end_stream()` 幂等发流 FIN；
     `H3TunnelReader`：DATA 载荷透传、未知帧跳过、流 FIN → EOF。
2. **varint 抽公共模块 `quicvarint.rs`**：hysteria2 原来的 4 个函数（长度/写/同步读/
   异步读）移入，hy2 与 h3 共用；补 RFC 9000 §A.1 官方向量测试。
3. **DoH over H3（`h3://`）**：`dnsup::Scheme::H3`（`h3://`/`http3://`，默认
   443、path 默认 `/dns-query`）；持久连接（5s keep-alive、60s 空闲重建）+ 一次失败
   重建重试；POST `application/dns-message`（带 accept/content-type/content-length），
   `:status != 200` 报错。`https://` 仍按 ALPN 优先 h2、不隐式切 h3。
4. **`naive+quic://`（HTTP/3 CONNECT）**：`Outbound::Naive` 增加 `h3: bool`；
   QUIC endpoint 用带 SO_MARK 的 UDP socket（防数据面二次接管）、ALPN=h3、5s
   keep-alive/60s 空闲；CONNECT 携 `proxy-authorization: Basic`；`socket=None`
   （QUIC 无底层 TcpStream，与 tuic/hy2 一样不与 offload 搭配）。
5. **显式边界（本轮不做，原因如实）**：
   - QPACK 只解静态表/字面量（引用动态表即报错；我们不广告任何动态表容量，
     服务端应以静态编码回应）；不开 QPACK encoder/decoder 单向流；
   - 无 0-RTT、无服务端推送、无 GOAWAY 重试；
   - naive H3 的 Basic 凭据仍依赖 TLS 内层保护（与 h2 形态同一告诫）。

## 理由

- h3 与 hy2 认证的差别只在「请求体帧化」与「响应持续读」，复用既有 QPACK/quinn
  部件是增量最小路径；`h2client`/`h3client` 对称也让两个 naive 形态共享 CONNECT
  语义（差异仅在传输）。
- `h3://` 显式 scheme（而非 https 自动升级）与 dae 的用法一致，也避免把「UDP 被
  封」的环境从可用 h2 误切到不可用 h3。

## 后果

- 正面：DoH 三传输（h1/h2/h3）+ DoQ 齐备；naive 两形态（h2/h3）齐备，协议家族
  与 DNS 域的对标余项各少一项。
- 负面/边界：如上第 5 条；另外实现期间踩到 **tokio 嵌套运行时**（在 `block_on`
  内再调 `H3Conn::new` 的 `block_on` → panic），已拆分为两段并写入 NOTES。

## 验证方式

- 单测：`quicvarint`（RFC 9000 §A.1 五组官方向量）、`h3client`
  （CONNECT 头块字节级 + DATA 帧编码）、`dnsup::parse` h3 默认值/路径、
  `outbound::parse_naive_url`（h3 标记、缺 userinfo 报错）；`cargo test --release`
  **208/208**。
- lab：`naive-h3-up` + `test-naive-h3`（Go/quic-go http3 参考服务端 + 上游 SO_MARK +
  逐块 Flush）——交互零延迟、512KB 逐字节（双向）、服务端 `proto=HTTP/3.0`、
  `offloaded_total=0`；`doh-h3-up` + `test-doh-h3`——两查询各答对、服务端
  `H3 request proto=HTTP/3.0` 恰好 2 次且**新建连接恰好 1 条**（连接复用断言）；
  另跑 `dns-bench` 单点 2/2。
- 回归：`verify` 9/9；`test-doh-h2` / `test-doh` / `test-doq` / `test-naive` /
  `test-tuic` / `test-hy2` 全 PASS（hy2 同时验证 varint 抽取无回归）。
- 真机：新二进制重启网关自检通过、组 66/66、generate_204 → 204、出口 IP 正常、
  0 panic。
- 文档：本 ADR + parity v2.4 + HTML v2.35 + NOTES §11.41。
