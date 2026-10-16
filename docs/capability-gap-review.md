# 能力缺口清点：dae（上游 Go）↔ sodama（全 Rust）

- **版本**：v1.2 · 2026-10-16（同日二更：eBPF 余项批次——§3 数据面全部余项落地，24 行判定全部「已完成」；ADR-0067 与 `phase2-devlog.md` §21。v1.1 = 本日 top 10 缺口 #1–#4 落地）
- **对照基线**：上游 clone `dae/`（`main@e3fee8f`，工作树 `2026-10-03`）+ 本仓库 `sodama/`（工作树 `2026-10-16`，能力缺口批次 #1–#4 之后）
- **本文档定位**：**一次性、逐项、可核查的能力清点**。不是覆盖度百分比（那是 `parity-status.md` 的口径），也不是排期（那是 `backlog.md` 的口径）。

## 口径与取证方法

**为什么不能直接采信两份自述文档。** `docs/parity-status.md`（v2.15）与 `docs/backlog.md` 都是**人工判断值**，已被本次清点证伪多处：

| 自述文档的说法 | 源码实测 | 差异性质 |
|---|---|---|
| `parity-status.md:17` 配置系统「≈73%」、解析面「语义逐条对齐」 | 解析面确实完整（`sodama/loader/src/config.rs:1108-1197` 覆盖 dae `Global`/`Dns`/`Group` 全部键），但 **48 个 global 键里只有 23 个被消费**（生效点见 §2） | 数字掩盖了「解析≠生效」 |
| `parity-status.md:14` 数据面「≈85%」 | 程序与 map 数量大体对得上（sodama 22 程序 = 12 TC + 6 cgroup + 1 sk_skb + 2 探针 + 1 XDP；dae 23 = 14 TC + 6 cgroup + 1 sk_skb + 2 探针；map 22 vs 24），但 `routing_map` 容量 64 vs dae 1024（`sodama/loader/src/rules.rs:39` vs `dae/Makefile:14`）这类**容量级**差异不在表内（v1.1：容量已补齐至 1024，见 §3 与 ADR-0066） | 覆盖度不含容量 |
| `backlog.md:61` D1「`include` 展开 ✅ 已完成（文档滞后修正）」 | 属实（`config.rs:1017` 循环检测） | 已吸收 |
| `README.md:9-10`（顶层）「8 个程序（7 个 TC + 1 个 sk_skb）+ 14 张 BTF map」 | 实为 **22 个程序**（`grep -c '#\[classifier\]' progs.rs` = 12，+6 cgroup +1 sk_skb +2 fentry/kprobe +1 XDP）与 **22 张 map**（`maps.rs` 22 个 `#[btf_map]`） | 顶层 README 仍停在 P9 时期 |
| `backlog.md:52` C1「余：`lan_egress` 角色未实现」 | 属实且是 §3 唯一缺的程序对（v1.2 已补：`sodama_lan_egress{,_l3}`，ADR-0067） | 已吸收 |

**取证方法**：全部结论来自**只读命令**（`grep`/`find`/`sed`/`wc`）对源码的静态阅读；本次未跑任何构建或测试。

**证据分级**（沿用 `docs/README.md:50-60`）：

- **源码实测**：静态阅读源码/统计得到（本文绝大多数条目）；
- **已实测**：有 `sodama/lab/`、`docs/phase2-devlog.md`、ADR 中的实跑记录可引（会显式标注）；
- **推断**：未验证的判断（本文用于「外部模块实现」「上游社区打包」等无法在 clone 内确认的事项）。

**一个刻意的取舍**：`dae/control/*.go` 有 **105 个非测试文件**。逐文件成行会让表退化成文件名清单，因此 §4 按**机制簇**成行，并在「能力/项」列**穷举该行覆盖的全部文件名**——105 个文件全部出现，一个不漏；判定按簇给出（簇内若有个别文件形态不对等，在「缺什么」里点名）。

---

## 1. CLI 面

对照对象：`dae/cmd/*.go`（rootCmd 与各子命令 flag）vs `sodama/loader/src/main.rs`（`Args`/`parse_args`/`usage()`/`run_subcommand`）。

| 能力/项 | dae 证据（文件:行号） | sodama 现状（文件:行号 或「无」） | 判定 |
|---|---|---|---|
| 顶层命令与 `--version` 输出 | `dae/cmd/cmd.go:23-31`（rootCmd）、`:36-41`（版本含 Go runtime/平台/许可证多行） | 无 `--version`；版本只在状态面 JSON（`sodama/loader/src/main.rs:8445`）与 `Cargo.toml` | **部分**：缺 CLI 版本输出 |
| 前台运行入口 | `dae/cmd/run.go:229-273`（`dae run`） | 无 `run` 子命令——不带子命令即前台运行（`main.rs:5558-5582`） | **已完成**（形态不同，语义等价） |
| `-c/--config <file>` | `dae/cmd/run.go:208`（required，缺失即 Fatal） | `main.rs:1392`（`Args.config`）、`:1751`（解析）、`:1812-1817`（默认 `~/.config/sodama/config.dae` → `/etc/sodama/config.dae`） | **已完成**（sodama 另有默认路径兜底） |
| 日志文件与轮转：`--logfile` / `--logfile-maxsize` / `--logfile-maxbackups`（lumberjack，含压缩） | `dae/cmd/run.go:209-211`（三个 flag）、`:252-262`（`lumberjack.Logger{MaxSize,MaxBackups,Compress}`） | `--log-file <path>`（`main.rs:1445,1754`）+ SIGHUP reopen（`main.rs:1601-1609`） | **部分**：缺内建大小/份数上限与压缩（需外部 logrotate） |
| `--disable-timestamp` | `dae/cmd/run.go:212` | 无：时间戳恒开（`main.rs:1460` `now_hms()`） | **未做** |
| pid 文件与 `--disable-pidfile` | `dae/cmd/run.go:40`（`/var/run/dae.pid`）、`:213`（flag）、`:446`（写） | 无 | **未做** |
| `validate -c <file>`（dry-run 规则编译） | `dae/cmd/validate.go:25-66`、`:72`（flag）；三条检查链：主 routing / dns.routing / fixed_domain_ttl（`:42,51,61`） | `sodama validate <config.dae>`（`main.rs:7572-7642`）：schema 校验 + 可编译/deferred 逐条列出 | **已完成** |
| `reload [pid] [-a/--abort]`（经 pid 文件发 SIGUSR1，轮询 `/var/run/dae.progress` 等结果） | `dae/cmd/reload.go:147-206`、`:260`（abort flag）、`:120-143`（等结果，60s 超时） | `sodama reload`（经状态 socket 同步等回执，`main.rs:7688-7703`）；**无 abort** | **部分**：缺 `--abort`（不掐已建连接） |
| `suspend [pid] [-a]` | `dae/cmd/suspend.go:20-49`、`:54` | `sodama suspend|resume`（`main.rs:7688-7703`）+ SIGUSR2 等价（`main.rs:877-879`）；**无 abort** | **部分**：缺 `--abort` |
| `trace -4/-6/-p/--port/--drop-only/-o`（按五元组过滤内核 trace；构建标签 `trace` 门控，官方构建含此标签） | `dae/cmd/trace.go:1`（`//go:build trace`）、`:30-75`（flag 在 `:68-73`）、`dae/.build_tags:1`（`trace`） | `sodama trace [--seconds N]`（`main.rs:7829-7863`）：读 `trace_pipe` 后按「含 sodama」字符串过滤 | **部分**：无协议/端口/IP 版本/丢弃过滤与输出文件 |
| `sysdump`（tar.gz：路由表/网卡/sysctl/nftables/iptables） | `dae/cmd/sysdump.go:26-56`（`:50` 打包）、`:158`（路由）、`:260-277`（nft/iptables） | `sodama sysdump [--socket][--out]`（`main.rs:7807-7827`）：status/rules/config/maps + `system_info_json()` 的**单份 JSON** | **部分**：缺网络/防火墙/路由现场（故障取证价值最高的一块） |
| `export outline`（配置 **schema** JSON，供 UI 开发者） | `dae/cmd/export.go:16-29` | 无等价：`sodama export-config`（`main.rs:7643-7646`）导出的是**用户配置实例** | **部分**：缺机器可读 schema 导出 |
| `completion [bash\|zsh\|fish]` | `dae/cmd/completion.go:17-33,57-59` + `dae/install/shell-completion/{dae.bash,dae.zsh,dae.fish}` | 无 | **未做** |
| 状态/运维子命令（status / metrics / reload / suspend / resume / sysdump / trace / sub-parse / dns-bench / export-config / extract-routing） | dae 无（daed/面板另有） | `main.rs:7568-7868`（`run_subcommand`）、`:5561-5577`（dispatch） | **已完成**（sodama 独有） |
| 拓扑与数据面 CLI（`--lan/--wan/--dual/--dae0/--dae0peer/--daens/--tproxy-port/--ebpf/--offload/--link-hdr/--xdp/--no-splice/--ebpf-debug/--ktls/--dump/--compile-dump/--proxy`） | dae 对应项来自 config（`lan_interface`/`wan_interface`/`tproxy_port`） | `main.rs:1375-1450`、`:1736-1795` | **已完成**（sodama 独有 CLI 面） |
| 节点/策略 CLI（`--dialer/--forward/--subscribe/--group/--listen-socks/--rules/--geodata-dir/--dns-upstream`） | dae 对应项来自 config 段 | `main.rs:1390-1422`、`:1750-1789` | **已完成**（sodama 独有） |
| 运行时调优 CLI（`--relay-idle-timeout/--udp-idle-timeout/--dial-timeout/--max-conns/--dial-mode/--sniffing-timeout-ms/--sniff-punt/--watch-config/--status-socket/--strict-config`） | dae 对应项来自 config 段 | `main.rs:1396-1447`、`:1757-1772` | **已完成**（sodama 独有） |
| 配置热驱动 `--watch-config`（inotify 毫秒级） | dae 无 CLI 对应（reload 靠信号） | `main.rs:1447`（flag）、`:1655-1658`（usage）、`watch.rs` | **已完成**（sodama 独有） |

> dae 的 `honk`（`dae/cmd/honk.go:17-29`）、`dae-ebpf-audit`、`gen_ebpf_sync`、`internal.AutoSu()` 见文末「不适用 / 已评估否决」。

---

## 2. 配置面

对照对象：`dae/config/*.go` + `dae/example.dae`/`dae/docs/zh/configuration/*` vs `sodama/loader/src/config.rs`（+ 生效点在 `main.rs`）。

| 能力/项 | dae 证据（文件:行号） | sodama 现状（文件:行号 或「无」） | 判定 |
|---|---|---|---|
| 段集合：`global`/`routing`/`dns`/`group`/`subscription`/`node`/`include` | `dae/config/config.go:156-163`（Config 结构）、`dae/config/decode.go:25`（段注册表） | `config.rs:1188-1197`（`KNOWN_SECTIONS`）、`:1248-1330`（逐段处理） | **已完成** |
| `include` 展开 + 目录相对约束 + 循环检测 | `dae/config/config_merger.go`（dfsMerge） | `config.rs:1036`（取 include）、`:1017`（`circular include is not allowed`）、`:2413`（测试) | **已完成** |
| `rule_set` 段（标准格式规则集 + URL 自动更新/缓存） | dae 无此段 | `config.rs:1192`（段名）、`:2051-2063`（提取）、`ruleset.rs:90-160`（磁盘缓存） | **已完成**（sodama 独有） |
| global 键**解析面**完整度 | `dae/config/config.go:19-63`（34 个 mapstructure 键） | `config.rs:1108-1164`（`GLOBAL_KEYS` **48 项** ⊇ dae 全部键 + sodama 自有键）、`:1223-1230`（未知键报错） | **已完成** |
| global 键**生效面** | dae：`cmd/run.go:264`（log_level 生效）、`dialer.go:260-265`（utls/tls_fragment/bandwidth/udphop 生效）、`control_plane.go:574,878`（fallback_resolver/tproxy_port_protect） | **生效 23 项**（`tcp_check_url` `main.rs:4555`、`udp_check_dns` `:4576`、`check_interval` `:4565`、`check_tolerance` `:4570`、`dial_mode` `:5666/5355`、`sniffing_timeout` `:5682/5368`、`auto_sniff_punt` `:5691/5376`、`bootstrap_resolver` `:5710/4201`、`log_file` `:5591`、`status_socket` `:5594`、`geodata_dir` `:5600`、`watch_config` `:5597`、`sub_cache_ttl` `:5393`、`sub_fail_ttl` `:5400`、`relay_idle_timeout` `:5635`、`udp_idle_timeout` `:5653`、`dial_timeout` `:5647`、`max_conns` `:5641`、`subscription_failover` `:4603-4606`、`subscription_update_interval` `:5109`、`probe_idle_cap` `:4609-4611`、`rule_set_update_interval`/`rule_set_cache_dir` `:4094-4097`）。**解析但不生效 22 项**：`tproxy_port`（仅 CLI，`main.rs:5625`）、`so_mark_from_dae`（数据面/控制面硬编码 `0x233`，`main.rs:97`）、`log_level`、`tcp_check_http_method`（探测硬编码 GET，`group.rs:980`）、`lan_interface`/`wan_interface`、`allow_insecure`（仅节点参数侧生效，`outbound.rs:1942`）、`disable_waiting_network`、`disable_thp`、`auto_config_kernel_parameter`、`tls_implementation`、`utls_imitate`、`tls_fragment`、`tls_fragment_length`、`tls_fragment_interval`、`pprof_port`、`mptcp`、`fallback_resolver`、`bandwidth_max_tx`、`bandwidth_max_rx`、`udphop_interval`（仅 `udphop-interval=` 节点参数，`outbound.rs:2347-2348,2418`）、`bpf_conn_state_map_size` | **部分**：缺「解析了但静默不生效」的显式告警与上列 22 项的行为 |
| `global.tproxy_port_protect` | dae：`config.go:21` 赋值到 `control_plane.go:878`，但 **C 数据面从未读取**（`kern/tproxy.c:215` 只有结构体字段） | sodama：`config.rs:1110` 允许该键，`ebpf-rs/src/common.rs:104` 也只有字段、无人读取 | **已完成**（两端同为空置；不是缺口） |
| dns 段键解析（9 键） | `dae/config/config.go:137-149` | `config.rs:1166-1176`（`DNS_KEYS`）、`:1390-1430`（逐键处理） | **已完成** |
| `dns.bind`（明文 DNS 监听地址） | `dae/control/control_plane.go:928-937`（`NewDNSListener`，供 AdGuardHome/mosdns 等外部 DNS 指上游） | 仅允许键（`config.rs:1171`），**无消费点**（`grep '"bind"' main.rs` 空） | **未做** |
| `dns.ipversion_prefer` 语义 | `dae/control/dns_preference_wait.go:16-26`（RFC 8305：先到 A 时等 AAAA 50ms）、`:151-181` | `main.rs:6837-6847`：只在「首选族已有新鲜缓存」时把非首选族回空 NOERROR——**无等待窗口** | **部分**：缺 50ms 偏好等待（先到 A 的场景仍会先返回 A） |
| `dns.fixed_domain_ttl` 格式校验 | `dae/cmd/validate.go:61-64`（`control.ParseFixedDomainTtl`） | `config.rs:1431-1446`（`域名: 秒数` 校验 + 行级诊断） | **已完成** |
| group 段 6 键（`filter`/`policy`/`tcp_check_url`/`check_interval`/`check_tolerance`/`udp_check_dns`） | `dae/config/config.go:102-114`、`component/outbound/dialer_group.go:77`（tolerance 生效） | `config.rs:2114-2125`（提取）、`main.rs:4546-4576`（组级覆盖全局）、`group.rs:275-328`（探测循环） | **已完成** |
| group 级 `tcp_check_http_method` | `dae/config/config.go:110` + `config/patch.go:34-41`（非法值回退 CONNECT） | 键被允许（`config.rs:1182`）但 `groups()` 不读（`:2114-2125`），探测写死 `GET /generate_204`（`group.rs:980`） | **未做** |
| `must_<组名>` 前缀糖（= `<组名>(must)`） | `dae/config/patch.go:71-95`（`patchMustOutbound`，含 fallback `must_x`）、`dae/docs/zh/configuration/routing.md:14`（文档明示 `must_groupname` 等价） | **已完成（v1.1）**：`map_outbound` 重写（`config.rs:1710`，`must_<名>` → `<名>(must)`，`must_rules` 保留；未定义组仍 K3 兼容回退 proxy 但 must 语义不丢）+ `apply_outbound_params`/`split_outbound_params`（`:1765/:1797`）修掉 `--config` 路径丢 `(must)`/`(mark:)` 参数的静默丢语义；投递侧成套落地（`flow.rs:326` `/`main.rs:2514-2529`/`:7279-7285`）；内核级实测 `test-must`（ADR-0066、devlog §20） | **已完成** |
| routing 规则函数覆盖（dip/sip/dport/sport/l4proto/ipversion/dscp/mac/pname/domain/geoip/geosite/not/and/mark/must） | `dae/component/routing/function_parser.go` | `rules.rs`（全函数集 + geoip/geosite 编译期展开）；与 dae 编译器**逐字节对拍 5/5**（`lab/parity.sh`，ADR-0010） | **已完成**（已实测） |
| `node` 内联节点 + 订阅 tag | `dae/config/config.go:158-159`、`dae/config/desc.go:11`（tag 语义） | `config.rs:2065-2080`（`inline_nodes`）、`:2034-2050`（`subscriptions`） | **已完成** |
| `node` 链式代理（`chains: 'tuic://A -> vmess://B'`） | `dae/example.dae:191`（示例）、`dae/docs/en/proxy-protocols.md:17`（协议表列出 Proxy chain）；实现位于外部模块 `daeuniverse/outbound`（`dae/go.mod:10,136` replace）——**推断**：该库负责 `->` 解析 | 无（`outbound.rs` 无 `->` 链解析；节点链接按单跳解析） | **未做**（证据分级：上游示例/文档为源码实测；「实现库支持」为推断） |
| 订阅语法 `http-file://` / `https-file://`（拉取失败回退磁盘缓存，成功即更新） | `dae/common/subscription/subscription.go:171-179`（scheme）、`:213-241`（先解析成功再落盘 `persist.d/<tag>.sub`） | **已完成（v1.1）**：`subscribe.rs:33` `normalize_url` 映射两 scheme，接入 `fetch`/`fetch_lenient`/`fetch_once`/URL 文件间接路径/`resolve_sub_url`；磁盘缓存/回退沿用既有机制（`subscribe.rs:639-680`，`sub-cache/<tag>.bin`）；内核级实测 `test-sub-file`（拉取成功+落盘+源掉线 SIGHUP 回退磁盘后仍可拨号；ADR-0066、devlog §20） | **已完成** |
| SIP008 订阅格式（ss 服务器的 JSON 列表） | `dae/common/subscription/subscription.go:71-104`（`ResolveSubscriptionAsSIP008`，优先于 base64 路径 `:218-224`） | 无 | **未做** |
| schema 校验（未知键/未知段/必填/行号诊断） | `dae/config/parser.go`（ParamParser）、`config.go:191-226`（required + 未知段） | `config.rs:1209-1230`（键白名单）、`:1239-1245`（未知段）、`:1486-1491`（dns.routing fallback 必填）、`:1199-1207`（文件:行号诊断） | **已完成** |
| `check_interval > 0` 校验（防调度器 panic） | `dae/config/patch.go:44-59`（全局与组级分别校验） | 无对应校验（`config.rs:2123` 只存字符串，`parse_duration_secs` 失败即忽略） | **未做** |
| `global.udphop_interval` | `dae/config/config.go:61` + `dialer/dialer.go:265`（传入 dialer） | 键允许但不读（`config.rs:1140`）；等价能力仅在节点 URL 参数 `udphop-interval=`（`outbound.rs:2347-2348,2418`） | **部分**：能力在，位置不同（需改节点链接） |

---

## 3. 数据面

对照对象：`dae/control/kern/tproxy.c`（`SEC(...)` 清单与 `SEC(".maps")` 定义）vs `sodama/ebpf-rs/src/{progs,cgroup,offload,trace,xdp,maps}.rs`。**ADR-0065 批次（L2/L3 变体、ringbuf、fentry/kprobe、XDP）已计入 sodama 现状，不再算缺口。**

| 能力/项 | dae 证据（文件:行号） | sodama 现状（文件:行号 或「无」） | 判定 |
|---|---|---|---|
| TC 分流程序族 5 角色 × L2/L3（lan_ingress/wan_egress/wan_ingress/wan_lan_ingress/lan_wan_egress） | `kern/tproxy.c:3224-3230`、`:3354-3360`、`:3403-3409`、`:3829-3835`、`:3858-3864` | `progs.rs:43-51,69-77,90-98,114-122,138-146`（10 个 + `link_hdr_len()` 判定 `main.rs:2067-2093`） | **已完成** |
| `lan_egress` 角色（L2/L3，容器/独立 netns 出口用法） | `kern/tproxy.c:2844-2850` | **已完成（v1.2）**：`sodama_lan_egress{,_l3}`（`progs.rs`；反向 conntrack 刷新）+ `attach_role` 的 LAN 分支双钩子（ingress+egress，`main.rs`）；内核级 `test-gaps`（hooks 断言）；ADR-0067 | **已完成** |
| 控制面交付/回程：`dae0peer_ingress` + `dae0_ingress` | `kern/tproxy.c:3870`、`:4030` | `progs.rs:150-151`（cb 传递 + sk_assign）、`:238-239`（回程 MAC/redirect + L3 剥头 `:206-236`） | **已完成**（L3 回程剥头为 sodama 有意偏离，见 ADR-0065） |
| cgroup 钩子 6 个（sock_create/release、connect4/6、sendmsg4/6） | `kern/tproxy.c:4200-4242`、挂载 `control_plane_core_bind.go:303-310` | `cgroup.rs:56-88`（6 个）+ 挂载 `main.rs:2324-2345`（`:2390-2394` 报 `N/6`） | **已完成** |
| `sk_skb` offload verdict | `kern/tproxy.c:4264`（`sk_skb/tcp_offload_redirect`） | `offload.rs:8-9`（`stream_verdict`）+ 用户态 `main.rs:3070-3115` | **已完成** |
| fentry/kprobe `skb_send_sock` 记账 | `kern/tproxy.c:4389`（fentry）、`:4397`（kprobe） | `trace.rs:210`（fentry）、`:226`（kprobe）；BTF 偏移注入 `main.rs:2188-2260` | **已完成** |
| XDP 路径 | dae 无 | `xdp.rs:24-25`（`sodama_xdp_observe`，恒 `XDP_PASS` 只计数）+ `--xdp`（`main.rs:1428,1784`） | **已完成**（sodama 独有） |
| ringbuf 事件通道 | `kern/tproxy.c:711`（256KiB）、`struct dae_event` `:696-709` | `maps.rs:80`（`event_ringbuf` 256KiB）、`common.rs:269-283`（`SodaEvent` 72B）、消费线程 `main.rs:1099-1136` | **已完成** |
| 事件类型覆盖（dae 10 类，其中 6/7 显式「保留、永不发出」） | `kern/tproxy.c:664-691` | **已完成（v1.2）**：0/1/2/3/4/5/8/9 全部实现（新增 3=BLOCKED_ALIVE、5=SYN_REBIND_REJECTED、9=SYN_REBIND_REROUTED；6/7 在 dae 侧即保留值，计数替代键 6/7 已补）；事件 5/9 由纯 SYN 重绑分支发送（`flow.rs`；同代拒改/异代重路由 + stats 5/12）；内核级 `test-gaps`；ADR-0067 | **已完成** |
| 事件限速键域 | `kern/tproxy.c:661`（`alive_block_rate_map`，注释 `:648-660` 说明 per-outbound 键 0..255）、`control/event_rate_contract.go:15-22` | **已完成（v1.2）**：键域对齐 dae（0..255 per-outbound（BLOCKED_ALIVE 用）、256..261 = blocked/redirect_rebind/overflow/syn_rebind/stateless_tcp/frag_tail；容量 262）；**per-CPU 实现保留**（aya-ebpf 无 64 位原子 CAS，ADR-0065 偏离，已文档化） | **已完成**（余：限速粒度 per-CPU） |
| `conn_state_map` 容量与可配 | `kern/tproxy.c:77`（`65536*4`）+ `:533`（max_entries）+ `config.go:62`/`control_plane.go:477`（`bpf_conn_state_map_size` 运行期改容量） | **已完成（v1.2）**：默认 262144（= dae 默认）；`bpf_conn_state_map_size` 经 `EbpfLoader::set_max_entries` 生效（**启动时**；运行期变更不做——ADR-0067 偏离 2） | **已完成** |
| `conn_state_map` 跨重启 pinning | `kern/tproxy.c:535`（`LIBBPF_PIN_BY_NAME`，注释「Loader may override pinning on cold start」） | **已完成（v1.2）**：加载后 pin 到 `/sys/fs/bpf/sodama/conn_state_map`；冷启动全表迁移（旧表→新表，generation 判定保证旧条正确失效）；内核级 `test-pinning`；ADR-0067 偏离 3 | **已完成** |
| 出口存活判定 `outbound_connectivity_map` + `wan_outbound_is_alive` | `kern/tproxy.c:116`（1536 项）、`:2857-2885`（读函数）、`:3169,3605,3758`（三处判定）、`control/connectivity.go:13-18` | **已完成（v1.2）**：`outbound_connectivity_map`（1536）+ `outbound_is_alive`（保留 outbound/53 放行，按 domain×ipver 查表）+ BLOCKED_ALIVE 事件（限速键 = outbound）+ 控制面 2s 健康投影（`dial_mode=ip` 且策略非 random/fixed 且**组非空**）；内核级 `test-alive`（组标死→阻断→恢复）；ADR-0067 | **已完成** |
| offload 背压 fuse | `kern/tproxy.c:274`（`tcp_offload_pause`，语义注释 `:262-266`：键在 = 暂停，不拆 psock） | **已完成（v1.2）**：map（LRU 8192）+ verdict pause 检查 + 看门狗两阶段 lift（DrainStart→Lift，纯函数单测）+ 用户态 drain 泵 + 注册清残留 + `SODAMA_FUSE_MAX_BACKLOG` 可调；内核级 `test-fuse`（阈值/无失败/成对退出）；真实触发需生产对端积压（ADR-0067 边界） | **已完成** |
| `fast_sock`（SOCKHASH 对拼） | `kern/tproxy.c:260` | `maps.rs:72`（`SockHash<SodaTuple, 4096>`）+ `offload_guard` 镜像 `:76` | **已完成** |
| `tcp_offload_sent` 按注册键记账 | `kern/tproxy.c:287` | **已完成（v1.2）**：记账（`PerCpuHashMap` + 键摘除回收）+ **per-key 背压 fuse**（见上行：backlog = 接收增量 − 内核推送 − 用户态泵，驱动 pause/lift）；ADR-0067 | **已完成** |
| `routing_map` 容量（= 可编译 match_set 上限） | `dae/Makefile:14`（`MAX_MATCH_SET_LEN ?= 1024`）、`kern/tproxy.c:67-68,359` | **已完成（v1.1）**：`common.rs:14`（`SODAMA_MAX_MATCH_SET_LEN = 1024`，与 dae 同口径；超限仍显式报错拒启动）、`maps.rs:18/24`（2×1024 槽）、扫描改内核 `bpf_loop`（`route.rs:253-260`；有界循环实测上限仅 ~217，见 devlog §20）；内核级实测 `test-rules-cap`（71 match_set + 高位规则命中；ADR-0066） | **已完成** |
| `lpm_array_map` / `routing_meta_map` / `active_routing_epoch_map` / `domain_routing_map`（双 epoch 热重载） | `kern/tproxy.c:320`、`:369`、`:377`、`:395` | `maps.rs:18,24,27,39`；槽切换 `main.rs:112-113,3956-3964` | **已完成** |
| `cookie_pid_map`（pname 采集）+ sodama 扩展 `dns_sender_pname_map` | `kern/tproxy.c:417` | `maps.rs:49`、`:55`；采集 `cgroup.rs`，反查 `main.rs:1282-1324` | **已完成** |
| `redirect_track`（容量/续租/清扫/容量告警） | `kern/tproxy.c:154`（65536，与 sodama 同）；dae 清扫在 Go 侧（`control/` 无独立文件，见 `conn_state_janitor.go:197-199`） | `maps.rs:36`（65536）+ 绑主校验 `progs.rs:269-281` + 清扫/告警 `main.rs:4403-4442` | **已完成**（含生产事故修复，`parity-status.md:57`，已实测） |
| `bpf_stats_map` / `alive_block_rate_map` | `kern/tproxy.c:592`、`:661`、`:540-600`（dae 键域 0..12：UDP/TCP 溢出、redirect 溢出/更新失败/重绑拒斥、SYN 重绑拒斥、无状态 TCP 直通、分片尾包直通、不支持的 L4、无主 WAN-ingress UDP、SOCKMARK 回退、事件丢弃、跨代重路由） | **已完成（v1.2）**：`sodama_stats_map` **键域对齐 dae 0..12**（拆 TCP/UDP 溢出键、补 REDIRECT_OVERFLOW/SYN_REBIND_REJECTED/STATELESS_TCP_PASSTHROUGH/FRAG_TAIL_PASSED/PARSE_UNSUPPORTED_L4/UNSOLICITED_UDP_SEEN/REBIND_REROUTED；键 10 SOCKMARK 为占位恒 0）；各 bump 点已铺（含 LAN TCP fail-closed）；13+ 为 sodama 自有（offload/探针/暂停）；容量 24；ADR-0067 | **已完成** |
| `routing_handoff_map`（首包/强制交接的**兜底**路由结果） | `kern/tproxy.c:295`（定义）、`:3618`（TCP SYN 首包）、`:3771`（UDP 强制交接）、`:2890`（lan_egress）；Go 侧**读取**：`control/utils.go:64-80`（`RetrieveRoutingResult` 先读 conn_state）、`:160-203`（读不到再读 handoff） | **已完成（v1.2）**：map（65536）+ 首包写入（TCP 纯 SYN / UDP 无 state；scratch 写入不占栈）+ 控制面兑底读取（`lookup_conn_outbound` 优先序 conn_state → handoff，30s TTL）；内核级 `test-gaps`（handoff 计数）；ADR-0067 偏离 5 | **已完成** |
| 实现态 scratch map（`parse_ctx_scratch_map` / `pkt_scratch_map` / `wan_egress_route_scratch_map` / `conntrack_args_map`） | `kern/tproxy.c:738`、`:1480`、`:1567`、`:1595` | 只有 `route_ctx_scratch_map`（`maps.rs:30`）——C 侧这些 scratch 是 clang/C 栈与辅助函数约束的产物，Rust/aya 路径以内联 + 单一 scratch 等价实现 | **已完成**（形态差异，非能力缺口；证据分级：**推断**（等价性未逐字节验证）） |
| L3 回程剥头与续租修正 | dae 无（对 L3 流的回程直接 redirect，包上留 veth 以太头） | `progs.rs:206-236`（`adjust_room(-14)` 剥头）、`:266-281`（L3 目标按回程续租）；ADR-0065「偏离清单」 | **已完成**（sodama 独有修正） |

---

## 4. 控制面子系统

对照对象：`dae/control/*.go` **105 个非测试文件**（`ls dae/control/*.go | grep -v _test | wc -l` = 105）vs `sodama/loader/src/*.rs` + `main.rs`。判定按机制簇，簇内文件全部列名。

| 能力/项（该行覆盖的 dae 文件） | dae 证据（文件:行号） | sodama 现状（文件:行号 或「无」） | 判定 |
|---|---|---|---|
| 加载器/ABI/生成绑定：`bpf_bpfeb.go`、`bpf_bpfel.go`、`bpf_stub.go`、`bpf_host_abi.go`、`bpf_utils.go`、`bpf_purge.go` | `control/bpf_utils.go:659-670`（`PARAM` 注入）、`:806`（map 句柄拷贝） | aya 装载 + 用户态 BTF 解析（`btfoff.rs`，14 项测试）+ 挂载 `main.rs:2116-2136` | **已完成**（形态不同：cilium/ebpf 生成绑定 vs aya 运行期解析） |
| 控制面主体与 datapath 装配：`control.go`、`control_plane.go`、`control_plane_core.go`、`active_control_plane.go`、`control_plane_parse.go`、`control_plane_datapath.go`、`control_plane_core_routing.go`、`control_plane_core_bind.go`、`control_plane_core_bind_event.go` | `control_plane.go:407`（sysctl 初始化）、`:868-878`（选项装配）、`control_plane_core_bind.go:172-183`（bindLan + 自动内核参数）、`:487+`（接口 pattern 注册） | `main.rs:4080-4158`（编译写槽）、`:2116-2136`（挂载）、`:4446-4518`（组构建）；**接口懒绑定/热插拔已补（v1.1）**：`ifwatch.rs`（`path.Match` glob + 1s 轮询 + `auto`→默认路由接口；`main.rs:6039-6044/6352-6374` 挂载与补挂/清理；ADR-0066 偏离 #1：轮询替代 netlink） | **已完成**（内核级实测 `test-hotplug`；余：接管时延 ~1s 未量化） |
| 代次/热重载/交接：`datapath_generation.go`、`fresh_datapath_state.go`、`generation_state.go`、`routing_epoch.go`、`routing_epoch_execution.go`、`routing_epoch_runtime.go`、`bpf_routing_epoch_attribution.go`、`control_plane_drain.go`、`control_plane_dialtarget.go`、`control_plane_dns.go` | `cmd/run.go:155-197`（`stagedReloadHandoff` 20+ 字段）、`run_reload.go:499`、`run_reload_worker.go:497` | `main.rs:108-110`（`EPOCH_SLOT_NUM=2`）、`:3956-3964`（切槽）、`:4189-4304`（reload 全流程）、`:6240-6258`（优雅退出） | **部分**：双 epoch 有；缺 `datapath_generation` 代次标记、fresh-datapath 交接与 drain 预算（dae 用于「换代期间新旧规则并存」的精确语义） |
| 规则匹配与分流 VM：`routing_matcher_builder.go`、`routing_matcher_userspace.go`、`domain_routing_tracker.go`、`real_domain_runtime.go`、`hash_utils.go`、`utils.go`、`addr.go` | `component/routing/matcher_builder.go`；`control/routing_matcher_userspace.go` 头注释：「用户态重放规则」 | `rules.rs`（数据面 VM 与用户态重放共用）、`main.rs:7214-7279`（域位图投影/回收）、`:3341-3357`（sniff-punt 重判） | **部分**：缺 `real_domain_runtime.go:1-16` 的「已验证真实域名」容量 8192 的 FIFO 确认集与负缓存（sodama 走 `sticky.rs` 粘滞 IP，语义相近但不等价） |
| TCP 流转发：`tcp.go`、`tcp_flow_binding.go`、`tcp_relay_core.go`、`tcp_relay_capabilities.go`、`tcp_relay_offload.go`、`tcp_copy_engine.go`、`tcp_copy_linux.go`、`tcp_copy_gather_linux.go`、`tcp_copy_other.go`、`tcp_copy_gather_other.go`、`tcp_sniff_policy.go` | `control/tcp.go`（relay 主体）、`tcp_copy_linux.go`（splice/copy 引擎） | `main.rs:3359-3773`（`handle_relay_conn`）、`:2523-2579`（copy pump）、`:2654-2731`（splice pump）、`reactor.rs`（epoll worker 池） | **已完成**（能力等价：splice 零拷贝、半关闭、SO_MARK 均实测，M1/M4） |
| TCP offload 生命周期：`tcp_offload_common.go`、`tcp_offload_hook.go`、`tcp_offload_links.go`、`tcp_offload_linux.go`、`tcp_offload_other.go` | `control/tcp_offload_hook.go`（fentry/kprobe 二选一）、`tcp_offload_links.go`（link 管理） | `main.rs:3070-3115`（try_offload）、`:2188-2260`（fentry/kprobe 挂载）、`:2867-2955`（看门狗）、`offload.rs` | **部分**：缺 `tcp_offload_pause` 背压 fuse 与 pause 键（同 §3） |
| UDP 会话与转发：`udp.go`、`udp_runtime.go`、`udp_flow.go`、`udp_flow_binding.go`、`udp_conn_state_tracker.go`、`udp_lifecycle.go`、`udp_profile.go` | `control/udp.go`、`udp_conn_state_tracker.go` | `main.rs:7372-7483`（`udp_nat_session`）、`:7540-7564`（janitor）、`:7297-7335`（会话读线程） | **已完成** |
| UDP 批处理/任务池：`udp_ingress_batch.go`、`udp_ingress_task.go`、`udp_task_pool.go`、`udp_write_batch.go` | `control/udp_ingress_batch.go`（recvmmsg 批量） | `main.rs:6556-6652`（`UdpRecvBatch` recvmmsg）、`:6438-6486`（`send_batch_to_udp` sendmmsg）；O7 四方对拍 20k pps 0 丢包 | **已完成**（已实测） |
| UDP endpoint pool / full-cone：`udp_endpoint_pool.go`、`udp_endpoint_lifecycle.go`、`udp_endpoint_reply.go`、`udp_endpoint_watcher.go` | `control/udp_endpoint_pool.go:20-27`（负缓存 `ErrEndpointFailed`）、`:29-40`（TTL/janitor） | 无 endpoint 池：每 `(client,orig_dst)` 会话一个透明回包 socket，容量 128 的 LRU 缓存（`main.rs:7339-7369`） | **未做**：缺端点复用池/负缓存/watcher（`backlog.md:70` E1 已登记） |
| 原始 UDP 回退：`raw_udp_linux.go`、`raw_udp_other.go` | `control/raw_udp_linux.go:14-19`（65507 上限校验） | 无 | **未做**（低相关：仅在特定透明回包形态下需要） |
| DNS 控制面：`dns.go`、`dns_control.go`、`dns_cache.go`、`dns_control_optimistic.go`、`dns_controller_bpf.go`、`dns_controller_cache.go`、`dns_controller_forwarder.go`、`dns_controller_handle.go`、`dns_controller_response.go`、`dns_controller_runtime.go`、`dns_listener.go`、`dns_resolve.go`、`dns_runtime.go`、`dns_utils.go`、`dns_wire_ttl.go`、`runtime_dns_accounting.go` | `control/dns_controller_*.go` 全套（含 `dns_controller_bpf.go:17-24` 的 BPF 投影更新任务堆 + 重试） | `dns.rs`（缓存 27 项测试）、`dnsup.rs`（DoT/DoH/DoQ）、`dnsroute.rs`（请求/应答路由）、`main.rs:6790-6988`（解析）、`:7081-7212`（UDP/TCP 服务）、`:7018-7077`（optimistic 刷新） | **部分**：缺 `dns.bind` 监听（见 §2）；BPF 投影为同步直写（dae 是带重试任务堆——`dns_controller_bpf.go:17-24`），失败路径的重试语义不对等 |
| DNS 偏好等待：`dns_preference_wait.go` | `control/dns_preference_wait.go:16-26`（50ms）、`:63-137`（注册/通知） | `main.rs:6837-6847`（仅过滤） | **部分**：同 §2 |
| 嗅探池：`packet_sniffer_pool.go` | `control/packet_sniffer_pool.go:17-22`（TTL 5s）、`:25-40`（会话表） | `sniffer.rs`（12 项测试）+ `quicsniff.rs`（QUIC Initial 解密） | **已完成** |
| 观测与事件：`runtime_stats.go`、`event_ringbuf.go`、`event_rate_contract.go`、`datapath_overflow_report.go`、`datapath_passthrough_report.go` | `runtime_stats.go:16-24`（1h 历史桶 + 250ms 采样）、`event_ringbuf.go`、`datapath_overflow_report.go` | `main.rs:8375+`（status JSON）、`:8630-8921`（Prometheus 文本）、`:1099-1136`（事件消费）、`:4370-4396`（overflow 清扫 + 事件上报）；**事件限速键域已对齐 dae（v1.2，0..261）** | **部分**：缺 1h 流量历史/速率窗口（dae 该字段服务 daed API）；溢出/直通等计数键已补齐（见 §3） |
| 告警节流：`alert_pacing.go` | `control/alert_pacing.go:14-22`（「持续条件合并为 N 秒一条 + 上报观察次数」） | `main.rs:4403-4442`（90% 容量固定步长告警）、`:989-995`（事件按类型限速 1/s） | **部分**：缺「持续条件 + 观察次数」抽象（只有固定步长单次告警） |
| 钩子生命周期：`tc_hook_set.go`、`tc_hook_handoff.go` | `control/tc_hook_set.go`、`tc_hook_handoff.go`（跨代钩子交接） | `main.rs:2116-2136`（挂载，link 持有）+ `HOOKS`（`:136`）；无摘钩/交接（依赖 TCX 进程退出自动摘） | **部分**：缺显式摘钩/交接用例（TCX 冷启动语义已实测，ADR-0009） |
| 状态清扫与 pinning：`conn_state_janitor.go`、`conn_state_pinning.go` | `conn_state_janitor.go:197-199`（含 routing_handoff 清扫，60s 级） | `main.rs:4370-4396`（conn_state）、`:4403-4442`（redirect_track）；**map pinning 已补（v1.2，见 §3）** | **已完成** |
| 拨号/健康/连接性：`dial.go`、`connectivity.go`、`node_latency.go` | `dial.go`（拨号参数与 must 语义）、`connectivity.go:13-18`（3 域 × 2 IP 版本 × 出口）、`node_latency.go:12-19`（延迟快照 API） | `group.rs`（探测/策略/`min_moving_avg`/容忍度/UDP DNS 探测）、`main.rs:3021-3039`（按组选 dialer） | **部分**：缺数据面连通性投影（`outbound_connectivity_map`，见 §3） |
| 会话管理与 abort：`session_manager.go` | `control/session_manager.go:143-151`（进程级 flow owner）、`cmd/reload.go:260`（`--abort`）、`cmd/run.go:164,795,835`（交接时 abort） | 无 | **未做**：reload/suspend 不能中止已建连接 |
| 系统集成：`netns_utils.go`、`sysctl.go` | `control/netns_utils.go`（建 netns/移网卡/tproxy 规则）、`sysctl.go:32`（`InitSysctlManager` + fsnotify 监视回写） | 脚本侧等价：`sodama/lab/gateway.sh:299-350`（sysctl/veth/路由/路由表 2023 全套 + `restore_sysctls`）；loader 自身**不自建**（`docs/deploy.md:19-21`） | **部分**：能力在（脚本级，gateway.sh 已实测）；systemd 路径需外部自备，且无「运行中 sysctl 被改回即纠正」的监视 |
| netkit 设备（替代 veth） | `control/netkit_linux.go:11-25`（`NetkitConfig`，含 `ScrubNone` 关 mark 擦除）、`netkit_netlink.go` | 无（`lab/gateway.sh` 用经典 veth） | **未做**（低相关：设备类型优化，非功能缺失） |
| 跨代资源租约：`egress_runtime.go`、`listener_runtime.go` | `egress_runtime.go:14-20`（出口租约引用计数）、`listener_runtime.go:8-14`（listener fd 跨代交接） | 无 | **已完成**（形态消解：sodama 单进程常驻 listener，reload 不重建 listener/不换代出口对象，此类交接问题不存在） |
| UDP GSO 批量发送：`anyfrom_pool.go` | `control/anyfrom_pool.go:29-40`（GSO 支持 + TTL 刷新节流 200ms） | `main.rs:6438-6486`（sendmmsg 批量）+ `config.rs` 无 GSO；无 TTL 刷新节流必要（无透明源端口复用） | **部分**：缺 GSO 聚合发送（批量路径已有，吞吐形态不同） |
| 多对象集维护：`datapath_janitor.go` | `control/datapath_janitor.go:17-25`（「one ringbuf reader for one BPF object set」） | `main.rs:1099-1136`（单对象集消费线程） | **已完成**（sodama 只有一套对象集，不需要多读者） |

---

## 5. 运维/发布面

对照对象：`dae/install/`、`dae/.github/workflows/`、`dae/Dockerfile`、`dae/Makefile`、`dae/hack/` vs 本仓库 `install/`、`sodama/lab/`、`.github/workflows/`、`docs/deploy.md`、`docs/openwrt.md`。

| 能力/项 | dae 证据（文件:行号） | sodama 现状（文件:行号 或「无」） | 判定 |
|---|---|---|---|
| systemd 单元 | `dae/install/dae.service:7-8`（崩溃环熔断）、`:11`（Type=notify）、`:25`（OOMScoreAdjust=-100）、`:40-42`（ExecStartPre validate / ExecStart / ExecReload） | `install/sodama.service:41-54`（骨架 ExecStart + ExecReload SIGHUP + capability 最小集 + LimitNOFILE）；**缺** ExecStartPre validate / StartLimit / OOMScoreAdjust / Type=notify | **部分** |
| 安装/卸载脚本 | `dae/install/package_after_install.sh`、`package_after_remove.sh`（发行包钩子） | `install/install.sh:1-232`（`--build/--no-build/--dry-run/--uninstall`，`:131-134` systemd 集成） | **部分**：安装/卸载/干跑已有；缺升级与失败回滚（`backlog.md:34` A9） |
| shell 补全 | `dae/install/shell-completion/{dae.bash,dae.zsh,dae.fish}` | 无 | **未做** |
| 容器镜像 + compose | `dae/Dockerfile:1-37`（多阶段 + geo 数据校验）、`dae/docker-compose.yml:1-11`（privileged/host net/pid） | 无（`panel/deploy` 是面板自身部署，不含引擎镜像） | **未做** |
| 发行工件与发行 CI | `dae/.github/workflows/release.yml:2,319-341`（tag 触发 + GH Release）、`prerelease.yml`、`daily-build.yml`、`nightly.yml` | 无（`.github/workflows/` 只有 `ci.yml`） | **未做** |
| 内核参数/前提文档 | `dae/docs/zh/user-guide/kernel-parameters.md:19-60`（sysctl 清单） | `docs/openwrt.md`（kernel fragment 18 项，`:35` NAMESPACES 硬前提）+ `docs/deploy.md:115-132`（sysctl 与恢复）+ `install/openwrt/kernel-fragment.config` | **已完成** |
| OpenWrt 打包（musl 交叉构建 + ipk/procd/uci） | dae 无（未见 OpenWrt 打包；证据：`find dae -iname '*openwrt*'` 空） | `install/openwrt/{Makefile,sodama.init,sodama.config,sodama-datapath,README.md}` + `lab/build-openwrt.sh` + `lab/openwrt-smoke.sh` + `docs/openwrt.md` | **已完成**（sodama 独有） |
| 一键网关脚本（含启动自检与失败回滚） | dae 无（依赖发行版网络管理） | `sodama/lab/gateway.sh`（`up/down`、sysctl 保存恢复、就绪才返回；ADR-0029，已实测） | **已完成**（sodama 独有） |
| 部署/使用文档 | `dae/docs/zh/user-guide/run-as-daemon.md`、`tutorials/{run-on-alpine,run-on-centos7,run-on-macos,dae-with-opnsense}.md` | `docs/deploy.md`（305 行）+ `docs/openwrt.md`（172 行） | **部分**：缺面向最终用户的多发行版教程（dae 的 macOS 教程对本项目不适用，见「不适用」） |
| 配置文档自动生成 | `dae/hack/ci/config-doc-generator.py`（由 config 结构生成 `docs/configuration/*`） | 无 | **未做** |
| 配置参考与迁移指南 | `dae/docs/{en,zh}/configuration/{routing,dns,separate-config,gaming-oriented-routing,external-dns}.md` | 无独立配置参考（散在 `sodama/README.md`、`docs/deploy.md`、`docs/examples/*.dae`）；`backlog.md:98` H2 已登记 | **部分** |
| 版本与 CHANGELOG | `dae/CHANGELOGS.md`（90KB，自动生成 `generate-changelogs.yml`）、`dae/Makefile:90`（版本注入 ldflags） | `Cargo.toml` 0.1.0，无 CHANGELOG（`backlog.md:29` A4） | **未做** |

---

## 6. 工程化/质量面

对照对象：`dae/*_test.go` 布局、`dae/fuzz` 类目标、`dae/control/kern/tests/`、`dae/.github/workflows/` vs sodama 的 `#[test]` 矩阵、`sodama/lab/`、`lab/matrix/`、CI。

| 能力/项 | dae 证据（文件:行号） | sodama 现状（文件:行号 或「无」） | 判定 |
|---|---|---|---|
| 单元测试规模 | 244 个 `*_test.go` / 39,453 行（`find dae -name '*_test.go' \| wc -l`） | 309 个 `#[test]`（`grep -rc '#\[test\]' sodama/loader/src/*.rs` 求和，含 `btfoff.rs` 14 项），分布 `dns.rs` 27 / `outbound.rs` 24 / `ss.rs` 17 / `group.rs` 16 | **部分**：用户态单测密度可观，但计数口径不可直接比（文件数 vs 用例数） |
| 数据面（BPF）单测 | `dae/control/kern/tests/{bpf_test.c,tcp_offload_header_test.c}` + `dae/Makefile:200-211`（`make ebpf-test` 用 `test_runtime` 在用户态跑 C 数据面逻辑） | **0 个**：`grep -rc '#\[test\]' sodama/ebpf-rs/src/*.rs` 全为 0 | **未做**（数据面逻辑仅由 lab 集成用例覆盖） |
| fuzz 目标 | 7 个：`cmd/runtime_supervisor_fuzz_test.go`、`component/sniffing/{quic,http,tls}_fuzz_test.go`、`sniffing/internal/quicutils/cipher_fuzz_test.go`、`control/{tcp_dns_frame,dns_cache}_fuzz_test.go` | 无 fuzz target（`find sodama -type d -name fuzz` 空）；`backlog.md:88` G3 已登记 | **未做** |
| 规则编译对拍 | dae 自身即基准 | `lab/parity.sh:1-40`（Go 侧 `lab/parity/run.sh` + Rust 侧 `--compile-dump`，5 个规则文件逐字节 diff） | **已完成**（sodama 独有，已实测） |
| netns 集成用例 | dae：仅有**带 mock 的 netns 作用域单测**（`dae/cmd/listener_netns_test.go:16-30` 打粧 `withDaeNetnsRequiredFunc`，不建真实 netns）；无真实 netns 拓扑夹具（未找到） | `lab/lab.sh`（4227 行，74 个 `test-*` 目标）、`lab/gateway.sh`、`lab/real-node-e2e.sh`、`lab/soak.sh` | **已完成**（sodama 独有，已实测） |
| 内核矩阵 | `dae/.github/workflows/kernel-test.yml:39-95`（CI 内多架构/内核构建与测试） | `lab/matrix.sh` + `lab/matrix/SUMMARY.md`（宿主 6.18.54-lts 9/9、QEMU 7.2.8 11/11，含 `l3-attach`/`xdp` 入门禁） | **部分**：矩阵有且更贴近数据面，但**不入 CI**（需 root/特权） |
| CI 覆盖 | 17 个 workflow（build/go-test+race+vet/bpf-test/kernel-test/lint/docker/release/prerelease/nightly/daily-build/ebpf-audit/check-docs/sync-docs/...） | `.github/workflows/ci.yml`（1 个：eBPF 对象构建 + loader 编译 + 单测；末尾注释显式声明不做特权加载、不加 `cargo fmt --check`） | **部分**：缺特权内核加载、数据面对象验证、lint、容器/发行流水线 |
| 静态检查/lint 门禁 | `dae/.golangci.yml`、`.github/workflows/lint.yml`、`.pre-commit-config.yaml` | 无 clippy/fmt 门禁（`ci.yml` 末尾注释说明 fmt 未 clean） | **未做** |
| 长稳/soak | `dae/scripts/control-memory-profile.sh`（内存剖面工具） | `lab/soak.sh`、`lab/perf/soak-curve.sh`（35/60min 曲线，RSS +3.1%）；72h 进行中（`docs/README.md:41,106`、`backlog.md:111`） | **部分**：脚本与判据齐备、短时可判；72h 未完成且不入 CI |
| 性能对拍 | dae 无 in-tree 基准对拍（`dae/scripts/` 无 bench） | `lab/perf/{run,scaling,udp,real,mem,mem-system,m2ab,codec-stress,soak-curve}.sh` + `lab/perf/gen-benchmark-report.py`（四方对拍 + 真实节点 `real.sh`） | **已完成**（sodama 独有，已实测） |
| 依赖/供应链审计 | `dae/.github/workflows/ebpf-audit.yml` + `dae/scripts/ebpf-audit.sh`、`.pre-commit-config.yaml` | 无（`docs/security-proposal.md` S0–S5 **待采纳**，`docs/README.md:107`） | **部分**：提案已含「fuzz ≥8 目标 / QEMU 特权加载 CI / cargo-deny」清单，未落地 |

---

## 不适用 / 已评估否决

| 项 | dae 证据 | 不列入缺口的理由 |
|---|---|---|
| `dae honk`（彩蛋命令） | `dae/cmd/honk.go:17-29` | 无功能意义，不构成能力 |
| `dae completion` 的**补全内容**归入 §5 未做；但 cobra 自动补全机制本身 | `dae/cmd/completion.go:16-33` | 已在 §5 记为「未做」，此处不重复计数 |
| `internal.AutoSu()` 自动 sudo 提权 | `dae/cmd/internal/su.go:1-60`、`dae/cmd/run.go:236-242`、`--disable-sudo`（`run.go:214`） | sodama 定位为 systemd/脚本托管的网关（`install/sodama.service`），提权由服务管理器负责；容器/OpenWrt procd 场景下自动 sudo 反而有害 |
| `dae-ebpf-audit`、`gen_ebpf_sync` 开发者工具 | `dae/cmd/dae-ebpf-audit/main.go`、`dae/cmd/generators/gen_ebpf_sync/` | C→Go 生成链路的开发工具，C 数据面已退役（ADR-0025），无对应物 |
| daed Web UI / GraphQL / 鉴权 / `component/daedns` | `dae/component/daedns/{client,router}.go` | 独立项目（daemon）；sodama 的等价形态是自研 `panel/`（`docs/backlog.md:118` 明示永久不在范围） |
| `unused_lpm_type` map | `dae/control/kern/tproxy.c:312` | C 侧类型占位（注释即表明未使用），无功能 |
| 上游已废弃配置键 `enable_local_tcp_fast_redirect`、`auto_config_firewall_rule` | `dae/config/config.go:38-42`（Deprecated 注释） | dae 自身已不消费；sodama 允许键但同样不消费，行为一致 |
| macOS / Windows 支持 | `dae/docs/zh/tutorials/run-on-macos.md` | 数据面依赖 Linux eBPF（`docs/backlog.md:120` 永久不在范围） |
| 发行版打包配方（AUR/PKGBUILD/deb/rpm） | dae 仓库内**未找到** in-tree 配方（`dae/install/` 只有包管理器**钩子**，`package_after_*.sh`） | dae 上游 in-tree 无配方，故不构成「dae 有我们没有」的对标缺口；仅作为 `backlog.md:32` A7 的自选项 |
| `dae/sysdump` 的 netfilter/iptables 抓取中的**规则下发**能力 | `dae/cmd/sysdump.go:260-277` | dae 只**读取**现场（不写规则）；sodama 数据面不依赖 nft/iptables（`docs/openwrt.md:123`），缺的是取证内容而非能力 |
| `tproxy_port_protect` | `dae/config/config.go:21` → `control_plane.go:878`，C 未读（`kern/tproxy.c:215`） | 上游空置功能，两端一致（详见 §2） |

---

## 汇总表

| 维度 | 行数 | 未做 | 部分 | 已完成 |
|---|---|---|---|---|
| 1. CLI 面 | 18 | 3 | 7 | 8 |
| 2. 配置面 | 21 | 5 | 3 | 13 |
| 3. 数据面 | 24 | 0 | 0 | 24 |
| 4. 控制面子系统 | 24 | 4 | 11 | 9 |
| 5. 运维/发布面 | 12 | 5 | 4 | 3 |
| 6. 工程化/质量面 | 11 | 3 | 5 | 3 |
| **合计** | **110** | **20** | **31** | **59** |

（表内每行判定均为三档之一；判定为「不适用」的项一律只在上一小节列出，不计入本表。
v1.1（2026-10-16 晚）：能力缺口批次 #1–#4 落地，4 行由「未做/部分」转「已完成」——§2 两行（must 糖、订阅 `-file` scheme）、§3 一行（`routing_map` 容量）、§4 一行（接口懒绑定/热插拔）。
v1.2（2026-10-16 深夜）：**eBPF 余项批次落地，§3 数据面 24 行全部「已完成」**——4 项未做（`lan_egress`/出口存活/背压 fuse/pinning）与 6 项部分（事件 3/5/9/限速键域/容量可配/stats 键/handoff）全部补齐（ADR-0067、devlog §21）；残留项为已文档化的偏离（per-CPU 限速、运行期容量、pinning 迁移方案等，见 ADR-0067 偏离清单）。）

读数提示：

- **「部分」占 31/110**——这是本次清点最重要的结论：sodama 的缺口形态以「能力在但语义/覆盖/形态不完整」为主，而非「整块缺失」。因此**不能把「部分」当已完成**（多数「部分」里都有一句话能说清缺什么）；反过来也不能把「部分」当「未做」（v1.2 后 §3 数据面已零「部分」——全部补齐；§4 的 11 项「部分」里有 8 项是可用的等价实现 + 一处明确差异）。
- **§4 的 7 项「已完成」集中在能力等价但形态消解的项**（跨代租约、多对象集、单进程 listener 等）；§4 的「部分」偏高是因为该维度按机制簇切分，簇内容易出现「主链路等价 + 边缘语义缺一项」。

---

## 我最有把握的 top 10 缺口

排序口径：**对「日常代理网关」的影响**（用户可感知 + 静默程度 + 触发概率）优先于工程化完备度。触发概率低或只在特定拓扑下出现的排后面。

| # | 缺口 | 为什么排这里 |
|---|---|---|
| 1 | ~~`must_<组名>` 前缀糖未实现且**静默映射为 proxy**（§2）~~ **✅ 已完成（本批 #1，ADR-0066、devlog §20；内核级实测 `test-must`）** | 唯一一条「写错了不报错、且给出错误语义」的缺口：配置里写 `must_proxy` 的流量会被当成 `proxy` 处理，DNS 也会被劫持处理（正是 `must` 想避免的）。它不以「配置错误」形式出现——只在 `validate`/启动日志的 outbound 映射行里能看到 `must_x -> proxy`（`main.rs:3875`，由 `config.rs:1719-1726` 的兜底分支产生），容易被当成正常路径。 |
| 2 | ~~订阅节点缓存**不落盘**（`https-file://` 语法 + `persist.d` 语义缺失，§2）~~ **✅ 已完成（本批 #2，ADR-0066；内核级实测 `test-sub-file`）** | 路由器重启 + 订阅源不可达 = 零节点启动。sodama 已有同类生产事故记录（`subscribe.rs:60` 注释：「生产实测：15:35 双源截断 → dialer=none」；另见 `parity-status.md:57`），而当前兜底只有**内存**缓存（重启即失，`main.rs:4646-4694`）与 `fetch_lenient`。日常网关的**可用性单点**。 |
| 3 | ~~接口懒绑定 / 热插拔缺失（`wan_interface: auto`、glob pattern、netlink add/remove 回调，§4）~~ **✅ 已完成（本批 #3，ADR-0066；内核级实测 `test-hotplug`；实现为 1s 轮询而非 netlink）** | 网关形态下设备变动是常态（USB 网卡、容器 veth、接口改名、拨号重建）。dae 在接口出现时自动补挂（`interface_manager.go:38-50` + `control_plane_core_bind.go:487+`），sodama 只在启动时按**精确名字**挂一次；变动后该接口流量**静默不被接管**。 |
| 4 | ~~`routing_map` 上限 64 vs 1024（§3）~~ **✅ 已完成（本批 #4，ADR-0066；`bpf_loop` 路线，内核级实测 `test-rules-cap`）** | 直接决定「大规则集能不能上线」：sodama 编译期报错拒启（不静默，但配置改不动）。参考点：`dae/example.dae:370-394` 的 routing 段只有 6 条规则，远低于上限——**推断**（未统计社区配置样本）：风险只在「规则数 > 64」的大配置上变现（如逐站点 `domain()` 白名单 + `pname` 组合），届时为硬门槛。 |
| 5 | TLS 分片与 uTLS 指纹开关全部不生效（`tls_fragment*`/`utls_imitate`/`tls_implementation`，§2） | 直接影响「能不能过」：SNI 分片是抗阻断的常用手段，且 dae 是全局开关一次生效。sodama 有自实现 Chrome-120 指纹（REALITY 路径），但**用户无法切换/分片**，也无法对普通 TLS 出站生效。 |
| 6 | 数据面「出口已死」判定缺失（`outbound_connectivity_map` + `wan_outbound_is_alive`，§3） | 出口全死时 sodama 仍把流量 redirect 到控制面，靠 relay 侧拨号失败兜底：每一次失败都要走完整 tproxy→relay→dial 链路，表现为**延迟上升与失败率放大**，而不是数据面直接丢弃/回退。 |
| 7 | global 生效面缺口里的「日常行为参数」：`fallback_resolver`、`allow_insecure`、`log_level`、`so_mark_from_dae`、`disable_thp`、`pprof_port`、`bandwidth_max_*`（§2） | 这些是**运维/排障日常**要用的旋钮：`log_level` 决定能否临时提详细度；`fallback_resolver` 决定节点域名解析的兜底；`allow_insecure` 是全局兜底（节点级已有）；`pprof_port` 决定能不能现场抓火焰图。逐项影响不大，但合起来是「调不动」的观感。 |
| 8 | reload/suspend 不带 `--abort`，且无 session_manager（§1/§4） | 换节点或改配置后，**已建连接继续走旧出口**直到自然结束（长连接可能是小时级）。对「改完立刻生效」的预期是直接违背。 |
| 9 | `conn_state_map` 容量 65536（dae 默认 262144）且**不可配**、无 pinning（§3） | 高并发网关（数万 flow）下提前触发溢出路径（有事件与计数，非静默），且重启后既有流状态全失（靠无状态放行兜底）。属于**容量安全边际**问题。 |
| 10 | 运维日常三件套：日志轮转三参缺失、无 pidfile、无 `--version`/`completion`（§1/§5） | 路由器上最现实的故障是**磁盘被日志吃满**（sodama 只有 SIGHUP reopen，需用户自配 logrotate）；pidfile/`--version`/补全是脚本化运维与工单取证的最低要求。 |

紧随其后（第 11–15，未进 top 10）：`tcp_offload_pause` 背压 fuse、UDP endpoint pool/full-cone 与 raw UDP 回退、订阅 SIP008 + 链式代理 `chains`、`dns.bind` 明文 DNS 监听出口、发布工程（Docker/发行包/发行 CI/lint 门禁/数据面单测/fuzz——`backlog.md` A 类之所以排最高优先级是从「从可运行到可分发」的角度，而本表按**日常网关影响**排序，故后置）。

**排序理由摘要**：前 4 名都是「会让用户直接感知或静默出错」的项（语义错、启不来、不接管、上不了线）——**v1.1：这 4 项已全部落地并内核级实测**（ADR-0066、`phase2-devlog.md` §20）；5–9 名是「能不能过 / 过得好不好 / 出问题能不能查」的项；第 10 名是把若干小项合并的运维基线缺口。数据面形态类（netkit、GSO、scratch map）与纯工程化类（CI 矩阵、打包）按此口径全部后置。
