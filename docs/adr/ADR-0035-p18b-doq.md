# ADR-0035：P18b DoQ（DNS over QUIC，RFC 9250）

- **状态**：已采纳（2026-10-04）
- **对应**：P18 缺口 #5 之 **b 段**；P18c `dns.routing` 待做
- **相关**：ADR-0034（P18a DoT/DoH、上游抽象）、ADR-0020（QUIC 栈/运行时）、
  NOTES §11.26；上游对照 `control/dns.go` 的 `DoQ`（quic-go）与
  `component/dnstransport/wire.go`（2 字节分帧）

## 背景

- dae 的 `quic://`（DoQ）语义（研究结论，`control/dns.go:415-525`、RFC 9250）：
  - ALPN `doq`，默认端口 853；
  - **线上 DNS ID 必须为 0**（§4.2.1；dae 在发送前直接改写 `data[0:2]=0`）；
  - 每查询一条 QUIC 双向流，查询 2 字节长度分帧；
  - 客户端**写完查询后要 FIN**，服务器在收到 FIN 后才应答（§4.2）；
  - 连接 `sync.Mutex` 复用；开流失败时换连接重试；超时用 8s（dae `doqExchangeTimeout`）；
  - 放弃查询时发 `DOQ_REQUEST_CANCELLED(0x3)`（§4.3.1）。
- mini 已在 P5-G3/G3b 建立 QUIC 基建（quinn 0.11 + `tuic::runtime()` + marked UDP socket +
  `tls::build_rustls_config`，含 `insecure` 自签校验路径）。

## 决策

1. **传输实现**（`dnsup.rs`）：`Scheme::Quic` → `exchange_quic()`：
   - `quic_conn()`：quinn 客户端端点（`Endpoint::new` **必须在 `runtime().block_on` 内**）、
     ALPN `[doq]`、`keep_alive=5s`、`max_idle_timeout=60s`、marked UDP socket；
     连接存 `Mutex<Option<QuicConn>>`（`born` + `close_reason()` 判陈旧/已关）；
   - `exchange_quic_once()`：锁内串行——`open_bi()` → 2B 分帧写查询（**ID 置 0**）→
     `send.finish()`（FIN）→ 读 2B + 应答 → `recv.stop(0x3)` 释放流槽；
     `tokio::time::timeout(5s)` 包住整次交换；
   - 失败**丢弃连接重试一次**（对照 dae 的 replaceConnection）；应答把客户端原始 ID 写回。
2. **健壮性**（本次踩坑的直接产物）：
   - `dnsup` 内三把锁（udp/persist/quic）改为**锁中毒恢复**
     （`lock().unwrap_or_else(|e| e.into_inner())`）：持锁者 panic 后按「丢弃旧连接
     重建」继续服务，而不是永久报「锁中毒」；
   - `dns_loop` / `handle_tcp_dns_conn` 对单次 `resolve_dns` 加
     `catch_unwind` 隔离（`upstream_errors` 计数 + 日志），**单次查询 panic 不再杀死
     DNS 线程**（此前一次 quinn panic 会让透明 DNS 永久失效）。
3. **lab 夹具**：`lab/proto-check/doq-server`（Go/quic-go 独立实现，ALPN doq、
   每流 2B 分帧、转发假 UDP DNS；日志 `DOQ-CONN`/`DOQ-QUERY`）+ 构建脚本
   `build-doq-server.sh`（复用 parity 的 dae-work 模块图，离线 GOPROXY=off）；
   夹具名 `doq.test`/`doq2.test`；会话 `doq-up` + `test-doq`（断言两次查询复用
   **1 条** QUIC 连接、ID 0/恢复）。
4. **文档**：ADR（本文）、NOTES §11.26、对标表 DNS 行、README、HTML v2.20。

## 理由

- 复用既有 QUIC 基建与 `runtime()`，零新依赖；接口与 DoT/DoH 的
  `exchange() -> Result<Vec<u8>, String>` 完全一致，`main.rs` 零改动。
- 按 RFC 9250 实现（ID 0 + FIN 后读 + 取消码），跨实现对端是 quic-go，
  与 dae 的 quic-go 客户端在线上行为同构；真实公网用 AliDNS DoQ 验证。

## 与 dae 的差异（如实）

- **0-RTT / EarlyConnection**：dae 用 `quic.EarlyConnection`；mini/quinn 用常规
  1-RTT 握手（首查询多一个 RTT，之后复用连接）。无 0-RTT 会话票缓存。
- **超时**：dae 单向 8s；mini 5s（与其它上游一致），可调。
- **连接池**：各 1 连接、锁内串行；无并发多连接。
- 无 DoQ 的 ECS/option 特殊处理（明文路径同）。

## 后果

- **正面（实测）**：
  - `cargo test --release` **136/136**（新增 DoQ ID 置零/恢复单测）；
  - lab：`doq-up`+`test-doq`——quic-go 服务端交叉验证：两次查询（doq.test/doq2.test）
    复用 1 条 QUIC 连接、应答正确、状态面 `upstream_scheme=quic`；
  - 真实公网：`quic://dns.alidns.com`（默认 853）解析 `www.baidu.com`/`www.qq.com`
    成功（真实 A 记录、证书校验通过、`upstream_errors=0`）；
  - 回归：`test-dot`（DoT 持久连接）在锁改动后仍通过；P18a 全部用例不受影响。
- **负面/代价**：单连接串行；`catch_unwind` 会吞掉 panic 现场（默认 panic hook 仍
  打印到 stderr/日志，且有计数）。
- **风险**：Alpine/musl 下 quinn 无影响（纯 Rust）；网络对 UDP 853 的封锁是部署
  环境问题（如实：AdGuard 的 853/784/8853 在本机网络被阻断，AliDNS 可达）。

## 验证方式（实测）

1. 单测：`cargo test --release`（`quic_id_zero_and_restore` + dnsup 其余 4 项）。
2. lab：`sudo lab/lab.sh doq-up && sudo lab/lab.sh test-doq`（需先
   `lab/proto-check/build-doq-server.sh`）。
3. 真实公网：lab 拓扑 + `--dns-upstream quic://dns.alidns.com`。
4. 回归：`test-dot`、`cargo test` 全量。

## 修订条件

- DoH3/h2（HPACK 编码侧或复用 h3 栈）与 `dns.routing`（P18c）；
- 需要并发连接池（DNS 线程池化）或 0-RTT 时；
- RFC 9250 之外的 DoQ 扩展（如共享 ticket、ECS 透传策略）出现需求时。
