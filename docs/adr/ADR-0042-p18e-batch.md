# ADR-0042：P18e 批量收尾（ss2022/http 出站 · 订阅热更新 · 并发上限 · 分片 · XDG · 嗅探增强 · CI/systemd）

- **状态**：已采纳（2026-10-04）
- **对应**：对标表剩余的工程化缺口批量收口——缺口 #6（ss2022/http）、#7（并发上限）、
  #8（热更新/udp_check）、#9（h2c/QUIC 识别）、#3（XDG）、#1（分片）、#11（systemd/打包）、#13（CI）
- **相关**：ADR-0016/0017（ss/trojan）、ADR-0030（嗅探）、ADR-0031（订阅/组）、
  ADR-0033（geodata）、ADR-0015/0022（转发面）、NOTES §11.33；
  对照实现：daeuniverse/outbound（ss/ssr；**无 SS2022**）、shadowsocks-rust（SIP022 参照）、
  dae `tproxy.c:1131/1214`（分片）、`common/assets/assets.go`（搜索目录）

## 背景

P18d 后剩余缺口多、单项都不大，但彼此独立，适合一次性批量收口并统一验收。其中需要
设计决策的是四项：SS2022 的密钥模型、订阅热更新的成员替换语义、HTTP 出站的范围、
以及分片/嗅探的「做什么、不做什么」边界。

## 决策

### 1. SS2022（SIP022）+ HTTP CONNECT 出站（缺口 #6）

- **SS2022**：新增方法 `2022-blake3-aes-128-gcm` / `2022-blake3-aes-256-gcm` /
  `2022-blake3-chacha20-poly1305`：
  - PSK 由用户在 URI 提供（标准 base64，长度必须等于密钥长度），**不做 EVP_BytesToKey**
    （SIP022 明确禁止；`parse_ss` 在 2022 分支硬校验长度）；
  - 子密钥 = `BLAKE3 derive_key("shadowsocks 2022 session subkey", PSK || salt)`；
  - TCP：客户端随机 salt（AES 方法 16B / chacha 32B）+ 长度域独立 AEAD 块、
    首块明文头带 timestamp/type/长度（+padding 上限 900）；
  - UDP：会话头 `session_id(8B) || packet_id(8B)`，重放窗口按 session 维护（上限 32）；
  - 与服务端 **双向独立**：无 EVP、无 SIP004 的 HKDF-SHA1 主密钥流程。
  - 依赖新增 `blake3 = "1"`（纯 Rust，无 C）。
- **HTTP 出站**：`Outbound::Http`——`parse_http` 支持 `http://[user:pass@]host:port`，
  拨号为 **CONNECT 隧道**（可选 Basic 认证、读取头到 `\r\n\r\n`、非 200 报错）；
  UDP 不支持（`supports_udp() == false`，调用方直连回退），与 dae/outbound 的 http 拨号器一致。
- **验收**：单测 12 项（SIP022 KAT/盐长/分块/UDP 会话；http 握手/认证/错误码）；
  lab 跨实现：ss2022 ↔ **shadowsocks-rust `ssserver`**（`ss2022-up`/`test-ss2022`）、
  http ↔ 独立 Python CONNECT 代理（`http-up`/`test-http`），均含 512KB 逐字节回显与协议/offload 互斥断言。

### 2. 订阅热更新（缺口 #8）

- SIGHUP 的 `do_reload` 在规则重载成功后追加 `reload_group_members`：
  重读 config → 重拉全部订阅（CLI + config，复用 `fetch_nodes`）→ `group::build_members`
  （按当前组名回查 filter）→ `GroupRuntime::replace_members`。
- **成员集热替换**：`GroupRuntime.inner` 改为 `RwLock<Arc<GroupInner>>`（成员+健康同锁），
  拨号/探测持 Arc 快照、不持有写锁；`replace_members` 整体替换，
  对 **name+tag 相同**的成员**继承 health（alive/last/EMA/hist）**，新成员默认健康，
  返回 `(新成员数, 继承数)`。
- **失败保留旧成员**：无节点（订阅全失败）/filter 后为空时不动原成员并告警——不做半截替换。
- 真机用法：改订阅内容或换 URL 后 `kill -HUP <pid>`；日志输出
  「订阅热更新：N 成员（继承 M 健康），组 X」，状态面 `group.members` 即时反映。

### 3. relay 并发上限 + udp_check_dns（缺口 #7/#8）

- `--max-conns N`（0=不限，`RELAY_MAX_CONNS`）：`handle_relay_conn` 入口超出即关闭 +
  `limit_rejected` 计数（状态面与 Prometheus `sodama_relay_limit_rejected`）；
  对照 dae relay 的并发限制语义（dae 是每出站最大连接数，这里先做全局上限）。
- 组参数 `udp_check_dns: 'dns.google:53[, ...]'`（组级 > 全局 `global.udp_check_dns`，
  取第一个；域名在构建时解析一次，失败禁用并告警）：
  健康探测对**支持 UDP 的成员优先走 UDP**（`dial_udp` + 最小 DNS A 查询 + 等应答，
  超时 3s/拨号 5s），失败**回退 TCP**；探测结果统一走 `record_probe`。
  对照 dae health check：UDP 能力节点以 UDP 检查为主。

### 4. 数据面分片与嗅探增强（缺口 #1/#9）

- **分片**（`ebpf-rs/src/parse.rs`，对照 dae `tproxy.c:1131/1214`）：
  - IPv4：`frag_off & 0x1fff != 0`（非首片）直接跳过——首片含完整 L4 头，代理重发
    由内核分片承担；避免把非首片当完整 TCP 头解析；
  - IPv6：分片扩展头 0x2c——非首片跳过；首片把偏移 +8B 后继续（扩展头链跳过逻辑同构）。
  改 eBPF 必须重建对象（`lab/build-ebpf-rs.sh`）。
- **h2c**（`sniffer.rs`）：识别 `PRI * HTTP/2.0` preface 后的首个 HEADERS 帧，
  内置**最小 HPACK 解码器**（静态表 61 项、前缀整数、Huffman 复用 `hpack.rs`）
  取 `:authority`；引用动态表/CONTINUATION 时按 No 回退 IP。
- **QUIC**：仅做 **Initial 包识别统计**（UDP 新会话首包长头且 ≥1200B，
  状态面 `sniffing.quic_initial`）——SNI 需解 Initial 加密（含 TLS 握手与 AEAD），
  不在本阶段做，如实不做。

### 5. 工程化补齐（缺口 #3/#11/#13）

- **geodata XDG**：搜索目录在 config 目录之后加入 `$XDG_DATA_HOME/dae` /
  `~/.local/share/dae`（HOME 回退）/ `$XDG_DATA_DIRS/*/dae`，系统目录兜底不变；
- **CI**：`.github/workflows/ci.yml`——固定工具链（nightly-2026-09-29 + bpf-linker 0.11.1
  + LLVM 23；本机验证过的组合）跑 loader `cargo build --release --locked`、
  `cargo test --release --locked`、eBPF 对象构建（build-std=core）与产物校验；
  fmt/clippy **刻意不入 CI**（生成件 `huffman_table.rs` 非 rustfmt-clean，容器内保证全绿优先）；
- **systemd/安装**：`install/sodama.service`（capability 最小集、`AmbientCapabilities`、
  SIGHUP `ExecReload`）+ `install/install.sh`（`--dry-run`/`--uninstall`，
  二进制/unit/配置/geodata 就位）+ `docs/deploy.md`。

## 理由

- SS2022 与 classic 共存的唯一干净做法是**在方法枚举内分叉**（密钥模型不同），
  URI 语义沿用 SIP002；不做 EVP 是协议要求，也是与 shadowsocks-rust 互操作的条件。
- 热替换成员用 `Arc<GroupInner>` 快照：拨号热路径零锁竞争、健康状态与成员同生命周期，
  避免「成员已换、健康数组错位」这一类经典丛发 bug；继承规则用 name+tag 是因为
  name 可能重复（不同订阅可以有同名节点），tag 是订阅来源，二者合一是最小可辨识键。
- UDP check 优先 + TCP 回退：单 UDP 探测在 UDP 被 QoS/阻断的环境里会误杀好节点，
  回退保证只增不减的探测敏感性；域名一次性解析避免探测路径反复走 DNS。
- 分片「非首片跳过」与控制面语义一致（dae 只处理首片）；h2c 用最小 HPACK 是因为
  客户端首请求几乎不引用动态表，收益/复杂度比最好；QUIC SNI 成本高，先只统计。
- CI/打包属于「别人拿到仓库能跑起来」的最低要求，单独收口。

## 后果

- 正面：协议家族补到 10/12（仅缺 ssr/juicity/naive 家族）；订阅热更新让「换订阅不重启」
  可用；组 UDP 检查与并发上限补齐运维面；分片/嗅探边界写死在代码与文档。
- 负面（如实）：
  - SS2022 未覆盖多用户 PSK（SIP022 的 userPSK 嵌套）、未做 replay 的持久化；
  - `--max-conns` 为全局上限，非 per-outbound；
  - UDP check 的域名目标要求构建期可解析（否则禁用）；探测 DNS 查询目标固定 `a.com`；
  - h2c 不支持动态表/CONTINUATION；QUIC 无 SNI；
  - CI 未跑 eBPF 加载类测试（需要特权内核环境）。

## 验证方式

- 单测：`cargo test --release` **174/174**（+18：ss2022 12 / http / h2c 4 / 热更新继承 / config 解析）；
- lab（root，串行）：`ss2022-up`+`test-ss2022`、`http-up`+`test-http`、
  `sub-reload-up`+`test-sub-reload`（2→1 成员 + 继承计数 + 拨号复测）、
  既有 `verify` 9/9 与协议梯无回归；
- 真机：订阅#2 网关 SIGHUP 热更新、`gateway.sh test`、HTTP/HTTPS 实测、0 panic；
- 文档：本 ADR + `docs/parity-status.md` v1.9 + `architecture-decision.html` v2.27 +
  `sodama/NOTES.md` §11.33。
