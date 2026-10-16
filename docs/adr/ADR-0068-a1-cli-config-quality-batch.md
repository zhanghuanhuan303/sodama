# ADR-0068：A1 批次——CLI/配置/控制面/工程质量（除工程打包）17 项落地

- **状态**：已采纳（2026-10-16）
- **对应**：用户决策「除了工程打包之外先把 a1 做完」——`docs/capability-gap-review.md`
  **附 A · A1 未做（20 项）** 中剔除 3 项发布工程（容器镜像 / 发行工件与发行 CI /
  版本与 CHANGELOG）后的 **17 项**全部落地（本批后 A1 未做 20 → **3**，部分 28 → **26**）
- **相关**：ADR-0016–0020（出站协议栈，链式代理复用）、ADR-0043（组分派）、ADR-0053（DNS 上游）、
  ADR-0067（出口连通性判定——本批修其投影缺陷）、`docs/phase2-devlog.md` §22（本批次记录）

## 背景

`docs/capability-gap-review.md` 附 A 固化后，A1（未做）20 项里除 3 项发布工程外，其余 17 项横跨
CLI（timestamp/pidfile/completion）、配置（`dns.bind`、group 级 `tcp_check_http_method`、
`chains`、SIP008、`check_interval` 校验）、控制面（UDP 端点池/full-cone、raw_udp、会话 abort、
netkit）、运维工件（shell 补全）与工程质量（BPF 单测、fuzz、配置文档生成、lint 门禁）。
本批一次收口，并入上一批（ADR-0066/0067）的既有架构，不引入新形态。

## 决策

### 1. CLI 三件套（#1/#2/#3）

- `--disable-timestamp`（`main.rs:1778/2125`）：`LOG_TS_OFF` 静态位 + `log_line` 统一出口
  （纯函数单测）；另加 sodama 扩展 config 键 `global.disable_timestamp`（`:6520-6526`，
  CLI 显式关优先）。
- pid 文件（`main.rs:7183-7185/7296-7312`）：**就绪后**写 `/var/run/sodama.pid`
  （对照 dae 的写点语义），`--disable-pidfile` 跳过写；退出无条件删除（不因 disable 跳过）。
- `completion bash|zsh|fish`（`main.rs:9580/9646+`）：脚本**内嵌二进制**（零外部文件依赖）；
  同时生成到 `install/shell-completion/sodama.{bash,zsh,fish}` 供安装脚本部署
  （`install/install.sh` 补全目录自动探测）。双份由单测锁定一致性。

### 2. 配置面五项（#4/#5/#7/#8 + chains #6）

- **`dns.bind`**（`main.rs:8295-8440`）：端点解析 `ip:port`（仅 UDP）/`udp+tcp://`/`tcp://`
  （对照 dae `ParseEndpoint`）；UDP/TCP 监听**复用透明 DNS 全链路**（routing/上游/缓存/位图），
  SERVFAIL 兑底；状态面 `dns.bind`/`dns.bind_queries`。
- **group 级 `tcp_check_http_method`**（`main.rs:5497-5511`、`group.rs:345/997/1021-1025`）：
  方法白名单 `is_valid_http_method`（等价 dae `IsValidHttpMethod`）；探测默认 HEAD（对齐 dae）；
  非法 global 值 warn 后回落 CONNECT（对照 `patchTcpCheckHttpMethod`）。
- **`check_interval > 0` 校验**（`config.rs:1390-1456`）：global 必须为正、group 不得为负
  （0 = 继承），行级诊断报错拒启（对照 `patchCheckInterval`，语义逐条对齐）。
- **SIP008**（`subscribe.rs:702-780`）：`version == 1 && servers != null` 判定（含 BOM 容忍）；
  每台映射为 `ss://` 链接后复用既有解析器（插件参数透传）；识别顺序 JSON 优先于 base64。
- **`chains` 链式代理**（`outbound.rs:2057-2160`）：按 `->` 硬切、名字字段 `#` 不参与拆分、
  各段必须完整链接；**左出口右首跳**——先经最左段拨出，再逐段 CONNECT，最右段执行到目标；
  中间跳经 loopback 桥（每跳一次用户态字节泵）。无 root 端到端 `lab/chain_test.sh`。

### 3. 控制面三项（#9/#10/#11）+ netkit（#12）

- **UDP 端点池 / full-cone**（`main.rs:674-697`、`udp_ttl_secs :8871+`）：
  `UdpFlowKey{client, dst:Option}`——`dst=None` = full-cone（同 client src 任意目标复用一出口
  端点，上行按包 `send_to`、回包按上游真实来源注入 `reply_send`）；分类 TTL（DNS 17s /
  QUIC·域名 300s / 代理地板 300s / NAT 默认）；负缓存（失败端点短期不再重试）；
  1s janitor 回收；`udp_nat.cone_sessions/negcache_hits` 状态面。
- **`raw_udp` 回退**（`main.rs:7419-7430/8826-8870`）：透明回包 `send_to` 因
  `EINVAL/EACCES/EPERM` 等失败时，按 errno 判定走 `SOCK_RAW + IPPROTO_UDP` 原始发送
  （65507 上限校验），计数 `udp_nat.raw_udp_fallbacks`。
- **会话管理与 abort**（`main.rs:9174-9250/10972-10982`）：TCP relay/reactor、UDP NAT 会话
  登记创建时代次（`generation`）；`reload --abort` = 关旧代会话 + conn_state scrub，
  `suspend --abort` = 关全部（`AbortScope`，纯函数 `abort_should_kill` 单测）。
- **netkit（lab 侧）**（`lab/lab.sh:376-396`）：控制面对优先
  `ip link add ... type netkit mode l2 scrub none`（`scrub none` 关 mark 擦除），
  **一次性创建成功**才用、否则回退 veth。

### 4. 工程质量四项（#16/#18/#19/#20）

- **`config-doc` 生成**（`main.rs:9747-9800`）：从 `config.rs` 的 `key_docs()` 登记表生成
  `docs/config-reference.md`（md/json 两格式）；drift 单测 `config_doc_registry_covers_all_keys`
  保证登记表 ↔ 生成物一致。
- **BPF 单测**（新 crate `sodama/ebpf-logic`）：纯逻辑抽成 host 可测函数
  （SYN 新流判定 / IPv4 头长与分片尾 / 限速窗口），数据面与测试**同源引用**（不复制）。
- **确定性 fuzz**（`loader/src/fuzz_smoke.rs`）：固定种子 xorshift 变异器 + 真实语料种子，
  覆盖 .dae 配置（含 include 展开）/DNS 报文/出站链接全家族/订阅（含 SIP008）/TLS CH/
  QUIC Initial/HPACK-QPACK；默认 4000 轮（release ≈1-2s），`SODAMA_FUZZ_ITERS` 可调。
- **lint 门禁**（`.github/workflows/ci.yml:106-120`）：`cargo fmt --check` +
  `cargo clippy --workspace --all-targets --locked -- -D warnings`；放行清单
  `sodama/Cargo.toml [workspace.lints.clippy]`（逐条附理由），本地清零。

### 5. 实测缺陷修复（本批由内核级用例抓到）

**出口连通性投影的冷启动死角**（`main.rs:581-626/6843-6853`，ADR-0067 遗留）：

- 症状：`outbound_connectivity_map` 是零初始化 Array（0 = 出口已死），而旧投影只遍历
  「组」——「无 group 段」配置（如 `lab/rules.udp.dae`）里路由给隐式 proxy 索引
  （`GROUP_INDEX_BASE = 0x2`），该索引永远不被覆盖 → **新流首包 100% 被门禁 SHOT**
  （debug 实测：`route outbound=0x2` 打出后 `udp_nat.sessions_total` 不增长）。
- 修复三层齐备：**①投影全键域**（`GROUP_INDEX_BASE..OUTBOUND_MUST_RULES`，未被组覆盖的
  索引写 1，顺带清 reload 后组集缩小留下的陈旧槽）；**②取图乐观初值**（take 后立即全量
  置 1，覆盖 GROUP_SET 就绪前的窗口）；**③投影循环先投影再 sleep 2s** + `do_reload`
  换代后立即再投影。
- 内核级验收：`test-udp-cone` FAIL → PASS；`verify` 与其余 cap 无回归。

## 理由

- 17 项里 11 项是「dae 有、sodama 缺」的直接对齐（timestamp/pidfile/completion/`dns.bind`/
  http method/`check_interval` 校验/SIP008/`chains`/端点池/raw_udp/abort/netkit），6 项是工程
  基线（补全工件/配置文档/BPF 单测/fuzz/lint）；全部落在既有模块内，无架构级新形态。
- 多项零散，但合起来直接改变「能不能用、改得动、查得到」的观感（A1 定位即此）。

## 后果（正/负）

**正**

- A1 未做 20 → **3**（全部为发布工程）；附 A 部分 28 → **26**（计数与汇总表同口径）。
- 明文 DNS 监听可作 AdGuard/mosdns 上游；`chains` 打通多跳；full-cone 端点复用降低
  出口 socket 压力；`--abort` 让「改完立刻生效」成立；netkit 在支持内核上替代 veth。
- 内核级 cap 9/11 → **11/11**（新增 `test-udp-cone`/`test-dns-bind`）；单测 310 → **326 + 3**；
  CI 增 lint 门禁（本地清零）；`docs/config-reference.md` 由 drift 单测锁定。

**负 / 代价**

- `chains` 每跳一次用户态字节桥（性能弱于原生多跳，只在多跳链路付出）；
- full-cone 仅对**直连型**出口生效（见偏离 1）；`dns.bind` UDP 单线程串行（见偏离 2）；
- 全键域投影每 2s 执行 1500 次 map set（µs 级，可忽略但需知晓开销恒定）；
- fuzz 为确定性形态（非 libFuzzer），覆盖靠语料种子与既定变异算子（见偏离 7）。

## 对 dae 的偏离清单

| # | 偏离 | 理由 | 证据分级 |
|---|---|---|---|
| 1 | full-cone 仅直连型出口（`relay.is_plain()`）；代理型仍 dest-affine | dae 的 UDP 端点池按 (client) 复用，但代理型协议每包目标在协议帧内——sodama 的代理型 relay 会话即目标，复用需改协议层 | 实测（代码路径 + `test-udp-cone` 走直连型） |
| 2 | `dns.bind` UDP 单线程串行（dae 有 16384 并发闸门） | lab/单机形态足够；过载由内核 socket 缓冲丢包兑底，不做 admission 队列 | 实测（线程数 = 1） |
| 3 | `dns.bind` reload 不重启监听（端点变更需重启进程） | dae 在 reload 时 `RestartDNSListener`；sodama 单进程监听常驻，重启语义更简单、且不丢在飞查询 | 实测 |
| 4 | abort 对 QUIC 系协议（tuic/hy2/juicity）只置 `stop` 位 | 这些协议无底层 TCP socket（QUIC 连接由 pump 持有），强制关闭需协议层 abort；置位后 pump 自行退出 | 实测 |
| 5 | `chains` 桥接到 loopback、每跳一次用户态字节泵；仅 TCP 链 | sodama 的链式是「拨号期链」而非「转发期链」；UDP 链无需求（低相关） | 实测（`lab/chain_test.sh`） |
| 6 | netkit 一次性创建（`mode l2 + scrub none` 同给），失败回退 veth；不做「先建后改」 | netkit 无「建后改 mode/scrub」操作；veth 回退保证旧内核可用 | 实测（QEMU 7.2.8 打出 netkit 行） |
| 7 | fuzz 为确定性变异测试（固定种子 + 语料），非 libFuzzer 目标 | libFuzzer 需 nightly + 外部工具链，与「不引入不可复现工具链」约束冲突 | 实测 |
| 8 | BPF 单测抽纯函数到 `ebpf-logic` crate（dae 用 `test_runtime` 跑 C） | aya-ebpf 目标不能跑 host 测试；同源函数引用避免逻辑复制漂移 | 实测 |
| 9 | 投影「未被组覆盖的索引写 1（乐观）」 | dae 的 outbound 空间总被组覆盖；sodama 有「无组段 + 隐式 proxy」形态，写 0 会阻断兜底流量 | 实测（本批缺陷复现） |
| 10 | `check_interval` 校验在 loader 校验链（行级诊断拒启）；dae 在 `config.New` patch 阶段报错 | 两者都是「不 panic 的报错」；sodama 的诊断带行号 | 推断（语义等价，报错形态不同） |

## 验证方式

- 单测：`cargo test --release` **326 通过**（+7 ignored）+ `ebpf-logic` **3 通过**；`fmt`/`clippy`
  清零（CI 门禁同款命令）。
- 内核级（QEMU 7.2.8，`QEMU_TIMEOUT=1500 sh lab/matrix.sh vm`）：
  `verify=PASS` 12/12；**`cap=11/11 PASS`**——既有 9 项 + 新增 `test-udp-cone`（双目标
  4 报文复用 1 端点）、`test-dns-bind`（应答/回包源/上游记录/二次查询命中缓存）。
- 无 root 用例：`lab/chain_test.sh`（链式 A->B 端到端）。
- 开发期由内核用例抓到的真实缺陷（已修）：出口连通性投影冷启动死角（见「决策 5」）；
  以及 `test-dns-bind` 的**断言锚定错误**（dns_probe 输出 `ancount=1 from=...`，旧断言
  `^from=` 永不匹配——VM debug8 实锤应答本身正常后修正断言）。

## 未做 / 边界

- 发布工程 3 项（容器镜像 + compose / 发行工件与发行 CI / 版本与 CHANGELOG）——用户明确
  本批排除，是 A1 的剩余尾单；
- `offload=FAIL` 在 QEMU 环境有既有抖动（devlog §19 已记录）：本批以「`connectivity_dead_groups=0`
  且 offload keys 已登记」证明连线已越过存活门禁、失败在 `kernel_bytes=0` 的内核对拼环节，
  与连通性修复无关（信息项）；
- `chains` 的 UDP 链、full-cone 的代理型出口、`dns.bind` 的运行期端点变更：真实需求触发时再做。
