# 能力缺口清点：dae（上游 Go）↔ sodama（全 Rust）

- **版本**：v1.5 · 2026-10-16（同日五更：**A2 批次（除工程打包）落地**——CLI 五件套（`--version`/日志轮转三参/`trace` 过滤器/`sysdump` 网络现场/`export outline`）/global 生效面 27 → 36/DNS `ipversion_prefer` 偏好等待与投影重试堆/1h 流量历史与告警节流/钩子生命周期用例/sysctl 被改回即纠正/UDP GSO/drain 预算/`real_domain_runtime`/systemd 单元强化共 19 项转「已完成」（ADR-0069、devlog §23）；清单口径：**未做 3 + 部分 7**。v1.4 = A1 批次（除工程打包）；v1.3 = 附 A 固化；v1.2 = eBPF 余项批次；v1.1 = top 10 #1–#4）
- **对照基线**：上游 clone `dae/`（`main@e3fee8f`，工作树 `2026-10-03`）+ 本仓库 `sodama/`（工作树 `2026-10-16`，A2 批次之后，HEAD `e5db7fd`）
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
| 顶层命令与 `--version` 输出 | `dae/cmd/cmd.go:23-31`（rootCmd）、`:36-41`（版本含 Go runtime/平台/许可证多行） | **已完成（v1.5）**：`--version`（`main.rs::version_text`/`print_version`：三行格式——版本+git sha / 运行时+平台 / 许可；sha 与 profile 由 `loader/build.rs` 尽力注入，无 git 时 `unknown`；在子命令分派前处理、无需 root）；状态面 JSON 与 `Cargo.toml` 并存（ADR-0069） | **已完成** |
| 前台运行入口 | `dae/cmd/run.go:229-273`（`dae run`） | 无 `run` 子命令——不带子命令即前台运行（`main.rs:5558-5582`） | **已完成**（形态不同，语义等价） |
| `-c/--config <file>` | `dae/cmd/run.go:208`（required，缺失即 Fatal） | `main.rs:1392`（`Args.config`）、`:1751`（解析）、`:1812-1817`（默认 `~/.config/sodama/config.dae` → `/etc/sodama/config.dae`） | **已完成**（sodama 另有默认路径兜底） |
| 日志文件与轮转：`--logfile` / `--logfile-maxsize` / `--logfile-maxbackups`（lumberjack，含压缩） | `dae/cmd/run.go:209-211`（三个 flag）、`:252-262`（`lumberjack.Logger{MaxSize,MaxBackups,Compress}`） | **已完成（v1.5）**：内建轮转——`--logfile`（= `--log-file` 同义）/`--logfile-maxsize <MB>`（默认 0 = 不轮转）/`--logfile-maxbackups <N>`（默认 3）；写满自动切分，旧份按 `.N.gz` 压缩（stored gzip），SIGHUP reopen 保留；与 lumberjack 的差异仅在份名（序号 vs 时间戳——ADR-0069） | **已完成** |
| `--disable-timestamp` | `dae/cmd/run.go:212` | **已完成（v1.4）**：`--disable-timestamp`（`main.rs:1778/2125`）+ config `global.disable_timestamp`（sodama 扩展键，`main.rs:6520-6526`，CLI 显式关优先）；`log_line` 单测锁定 | **已完成** |
| pid 文件与 `--disable-pidfile` | `dae/cmd/run.go:40`（`/var/run/dae.pid`）、`:213`（flag）、`:446`（写） | **已完成（v1.4）**：就绪后写 `/var/run/sodama.pid`（`main.rs:7183-7185/7296-7308`）+ `--disable-pidfile`（`:1780/2126`）；退出无条件删除（对照 dae defer，`:7310-7312`） | **已完成** |
| `validate -c <file>`（dry-run 规则编译） | `dae/cmd/validate.go:25-66`、`:72`（flag）；三条检查链：主 routing / dns.routing / fixed_domain_ttl（`:42,51,61`） | `sodama validate <config.dae>`（`main.rs:7572-7642`）：schema 校验 + 可编译/deferred 逐条列出 | **已完成** |
| `reload [pid] [-a/--abort]`（经 pid 文件发 SIGUSR1，轮询 `/var/run/dae.progress` 等结果） | `dae/cmd/reload.go:147-206`、`:260`（abort flag）、`:120-143`（等结果，60s 超时） | `sodama reload [--abort]`（经状态 socket 同步等回执，`main.rs:7688-7703`）；**`--abort` 已补（v1.4）**：切代后关旧代已建连接 + conn_state 清扫（`main.rs:9174-9250`、`:10972-10982`；纯函数 `abort_should_kill` 单测） | **已完成** |
| `suspend [pid] [-a]` | `dae/cmd/suspend.go:20-49`、`:54` | `sodama suspend|resume [--abort]`（`main.rs:7688-7703`）+ SIGUSR2 等价（`main.rs:877-879`）；**`suspend --abort` 已补（v1.4）**：关闭全部已建连接（`AbortScope::All`，`main.rs:9176-9190`） | **已完成** |
| `trace -4/-6/-p/--port/--drop-only/-o`（按五元组过滤内核 trace；构建标签 `trace` 门控，官方构建含此标签） | `dae/cmd/trace.go:1`（`//go:build trace`）、`:30-75`（flag 在 `:68-73`）、`dae/.build_tags:1`（`trace`） | **已完成（v1.5）**：`sodama trace [--seconds N] [-4|-6] [-p|--l4-proto tcp|udp] [-P|--port N] [--drop-only] [-o <file>]`（flag 面对齐 dae）——过滤位图（协议/端口/IP 版本/drop-only）经 `SodaTraceFilter`/`trace_filter_map` 在**内核侧**先裁（4 个判决点发 `SODAMA_EVENT_TRACE`，判决在 `SodaEvent.pad[0]`），CLI 侧按条件二次过滤；daemon 落盘 `/run/sodama-trace.log`（不可写退 `/tmp`；`trace_line_stream_filter` 单测——ADR-0069） | **已完成** |
| `sysdump`（tar.gz：路由表/网卡/sysctl/nftables/iptables） | `dae/cmd/sysdump.go:26-56`（`:50` 打包）、`:158`（路由）、`:260-277`（nft/iptables） | **已完成（v1.5）**：`sysdump --out *.tar.gz`（新 `loader/src/dump.rs`：自实现 ustar + **stored gzip**，不引入压缩依赖）——打包状态面 JSON、路由表、网卡、sysctl、nft/iptables、日志尾部与 version.txt 等现场；`tar xzf` 实测可解（ADR-0069） | **已完成** |
| `export outline`（配置 **schema** JSON，供 UI 开发者） | `dae/cmd/export.go:16-29` | **已完成（v1.5）**：`sodama export outline`——导出 `key_docs()` 登记表的机器可读 schema（与 `config-doc` 同源；`run_subcommand` 的 `export outline` 分支 `export_outline_json`）；`export-config` 仍导用户配置实例（ADR-0069） | **已完成** |
| `completion [bash\|zsh\|fish]` | `dae/cmd/completion.go:17-33,57-59` + `dae/install/shell-completion/{dae.bash,dae.zsh,dae.fish}` | **已完成（v1.4）**：`sodama completion bash\|zsh\|fish`（`main.rs:9580/9646+`，内嵌脚本）+ 预生成副本 `install/shell-completion/sodama.{bash,zsh,fish}` + `install/install.sh` 部署（补全目录自动探测） | **已完成** |
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
| global 键**生效面** | dae：`cmd/run.go:264`（log_level 生效）、`dialer.go:260-265`（utls/tls_fragment/bandwidth/udphop 生效）、`control_plane.go:574,878`（fallback_resolver/tproxy_port_protect） | **生效 27 → 36 项（v1.5，ADR-0069）**（`tcp_check_url` `main.rs:4555`、`udp_check_dns` `:4576`、`check_interval` `:4565`、`check_tolerance` `:4570`、`dial_mode` `:5666/5355`、`sniffing_timeout` `:5682/5368`、`auto_sniff_punt` `:5691/5376`、`bootstrap_resolver` `:5710/4201`、`log_file` `:5591`、`status_socket` `:5594`、`geodata_dir` `:5600`、`watch_config` `:5597`、`sub_cache_ttl` `:5393`、`sub_fail_ttl` `:5400`、`relay_idle_timeout` `:5635`、`udp_idle_timeout` `:5653`、`dial_timeout` `:5647`、`max_conns` `:5641`、`subscription_failover` `:4603-4606`、`subscription_update_interval` `:5109`、`probe_idle_cap` `:4609-4611`、`rule_set_update_interval`/`rule_set_cache_dir` `:4094-4097`、**`lan_interface`/`wan_interface`（v1.1，ADR-0066：ifwatch 热插拔/模式匹配/config 回填）**、**`bpf_conn_state_map_size`（v1.2，ADR-0067：启动时生效）**、**`tcp_check_http_method`（v1.4：global 级 + group 覆盖，`main.rs:5497-5511`）**、**v1.5 新增 9 键：`log_level`、`so_mark_from_dae`（控制面自身 socket SO_MARK 全链可配）、`allow_insecure`（全局默认，节点级优先）、`disable_waiting_network`（+启动等待网络 30s 上限）、`disable_thp`（本进程 `PR_SET_THP_DISABLE`）、`auto_config_kernel_parameter`（+sysctl 被改回即纠正，新 `loader/src/sysctl.rs`）、`mptcp`、`fallback_resolver`、`udphop_interval`（全局默认）**）。**「不生效」余项 9 项（v1.5；余项均有显式告警或 ADR 记录——不再静默，`INERT_KEYS` 告警表已清空）**：`tproxy_port`（按设计仅 CLI `--tproxy-port`）、`tls_fragment`/`tls_fragment_length`/`tls_fragment_interval`（v1.5 已接线，但 CH 分片仅自实现 TLS 路径（REALITY）生效、rustls/quinn 出站不分片——ADR-0069 偏离 2）、`utls_imitate`/`tls_implementation`（v1.5 接受 chrome 口径并显式告警，指纹固定 Chrome-120——偏离 4）、`pprof_port`（v1.5 起为本机诊断端口（`/` 与 `/json`），非 Go pprof 火焰图——偏离 5）、`bandwidth_max_tx`/`bandwidth_max_rx`（v1.5 起进程级令牌桶；限额生效时 relay 新连接走拷贝泵——偏离 3） | **已完成**（v1.5：9 键转生效、9 项按设计/偏离显式记录，不再静默；ADR-0069） |
| `global.tproxy_port_protect` | dae：`config.go:21` 赋值到 `control_plane.go:878`，但 **C 数据面从未读取**（`kern/tproxy.c:215` 只有结构体字段） | sodama：`config.rs:1110` 允许该键，`ebpf-rs/src/common.rs:104` 也只有字段、无人读取 | **已完成**（两端同为空置；不是缺口） |
| dns 段键解析（9 键） | `dae/config/config.go:137-149` | `config.rs:1166-1176`（`DNS_KEYS`）、`:1390-1430`（逐键处理） | **已完成** |
| `dns.bind`（明文 DNS 监听地址） | `dae/control/control_plane.go:928-937`（`NewDNSListener`，供 AdGuardHome/mosdns 等外部 DNS 指上游） | **已完成（v1.4）**：`parse_dns_bind`（`main.rs:8295-8327`：`ip:port` = 仅 UDP / `udp+tcp://` / `tcp://`）+ UDP/TCP 监听（`:8377+/:8434+`，复用透明 DNS 全链路 routing/上游/缓存/位图；SERVFAIL 兑底）；状态面 `dns.bind`/`dns.bind_queries`；内核级实测 `test-dns-bind`（应答/回包源/上游记录/二次查询命中缓存） | **已完成**（余：UDP 单线程串行、reload 不重启监听——ADR-0068 偏离清单） |
| `dns.ipversion_prefer` 语义 | `dae/control/dns_preference_wait.go:16-26`（RFC 8305：先到 A 时等 AAAA 50ms）、`:151-181` | **已完成（v1.5）**：50ms 偏好等待（新 `loader/src/dns_pref_wait.rs`：非首选族在缓存未命中、即将上行时登记 50ms 等待，首选族答案到达即取消；缓存命中路径不登记）+ 原「首选族有新鲜缓存 → 非首选族回空 NOERROR」路径保留（ADR-0069） | **已完成** |
| `dns.fixed_domain_ttl` 格式校验 | `dae/cmd/validate.go:61-64`（`control.ParseFixedDomainTtl`） | `config.rs:1431-1446`（`域名: 秒数` 校验 + 行级诊断） | **已完成** |
| group 段 6 键（`filter`/`policy`/`tcp_check_url`/`check_interval`/`check_tolerance`/`udp_check_dns`） | `dae/config/config.go:102-114`、`component/outbound/dialer_group.go:77`（tolerance 生效） | `config.rs:2114-2125`（提取）、`main.rs:4546-4576`（组级覆盖全局）、`group.rs:275-328`（探测循环） | **已完成** |
| group 级 `tcp_check_http_method` | `dae/config/config.go:110` + `config/patch.go:34-41`（非法值回退 CONNECT） | **已完成（v1.4）**：group 级优先、global 兑底（`main.rs:5497-5511`）；方法白名单 `is_valid_http_method`（`group.rs:1021-1025`，等价 dae `IsValidHttpMethod`；非法 global 值 warn 后回落 CONNECT）；探测默认 HEAD（`group.rs:345/997`，对齐 dae） | **已完成** |
| `must_<组名>` 前缀糖（= `<组名>(must)`） | `dae/config/patch.go:71-95`（`patchMustOutbound`，含 fallback `must_x`）、`dae/docs/zh/configuration/routing.md:14`（文档明示 `must_groupname` 等价） | **已完成（v1.1）**：`map_outbound` 重写（`config.rs:1710`，`must_<名>` → `<名>(must)`，`must_rules` 保留；未定义组仍 K3 兼容回退 proxy 但 must 语义不丢）+ `apply_outbound_params`/`split_outbound_params`（`:1765/:1797`）修掉 `--config` 路径丢 `(must)`/`(mark:)` 参数的静默丢语义；投递侧成套落地（`flow.rs:326` `/`main.rs:2514-2529`/`:7279-7285`）；内核级实测 `test-must`（ADR-0066、devlog §20） | **已完成** |
| routing 规则函数覆盖（dip/sip/dport/sport/l4proto/ipversion/dscp/mac/pname/domain/geoip/geosite/not/and/mark/must） | `dae/component/routing/function_parser.go` | `rules.rs`（全函数集 + geoip/geosite 编译期展开）；与 dae 编译器**逐字节对拍 5/5**（`lab/parity.sh`，ADR-0010） | **已完成**（已实测） |
| `node` 内联节点 + 订阅 tag | `dae/config/config.go:158-159`、`dae/config/desc.go:11`（tag 语义） | `config.rs:2065-2080`（`inline_nodes`）、`:2034-2050`（`subscriptions`） | **已完成** |
| `node` 链式代理（`chains: 'tuic://A -> vmess://B'`） | `dae/example.dae:191`（示例）、`dae/docs/en/proxy-protocols.md:17`（协议表列出 Proxy chain）；实现位于外部模块 `daeuniverse/outbound`（`dae/go.mod:10,136` replace）——**推断**：该库负责 `->` 解析 | **已完成（v1.4）**：`parse_chain`（`outbound.rs:2057-2085`，按 `->` 硬切、各段完整链接校验、名字字段 `#` 不参与拆分）+ `chain_dial`（`:2086-2160`：**左出口右首跳**——先经最左段拨出，再逐段向其余跳发 CONNECT，最右段执行到目标）+ loopback 桥（`chain_bridge_port`/`chain_pump`）；无 root 端到端 `lab/chain_test.sh` | **已完成**（边界：仅 TCP 链；每跳一次用户态字节桥——ADR-0068） |
| 订阅语法 `http-file://` / `https-file://`（拉取失败回退磁盘缓存，成功即更新） | `dae/common/subscription/subscription.go:171-179`（scheme）、`:213-241`（先解析成功再落盘 `persist.d/<tag>.sub`） | **已完成（v1.1）**：`subscribe.rs:33` `normalize_url` 映射两 scheme，接入 `fetch`/`fetch_lenient`/`fetch_once`/URL 文件间接路径/`resolve_sub_url`；磁盘缓存/回退沿用既有机制（`subscribe.rs:639-680`，`sub-cache/<tag>.bin`）；内核级实测 `test-sub-file`（拉取成功+落盘+源掉线 SIGHUP 回退磁盘后仍可拨号；ADR-0066、devlog §20） | **已完成** |
| SIP008 订阅格式（ss 服务器的 JSON 列表） | `dae/common/subscription/subscription.go:71-104`（`ResolveSubscriptionAsSIP008`，优先于 base64 路径 `:218-224`） | **已完成（v1.4）**：`parse_sip008`（`subscribe.rs:702-752`：`version=1` + `servers[]` → ss 节点）；识别顺序对齐 dae（JSON 优先于 base64，`:758-761`）；不支持项逐条报错不静默丢（`:777`）；单测 `sip008_maps_to_ss_nodes` | **已完成** |
| schema 校验（未知键/未知段/必填/行号诊断） | `dae/config/parser.go`（ParamParser）、`config.go:191-226`（required + 未知段） | `config.rs:1209-1230`（键白名单）、`:1239-1245`（未知段）、`:1486-1491`（dns.routing fallback 必填）、`:1199-1207`（文件:行号诊断） | **已完成** |
| `check_interval > 0` 校验（防调度器 panic） | `dae/config/patch.go:44-59`（全局与组级分别校验） | **已完成（v1.4）**：`validate_check_intervals`（`config.rs:1378-1430`）：global 与 group 级分别校验，0/负值/不可解析 → 行级诊断报错拒启（单测锁定） | **已完成** |
| `global.udphop_interval` | `dae/config/config.go:61` + `dialer/dialer.go:265`（传入 dialer） | **已完成（v1.5）**：global 键生效——节点未写 `udphop-interval=` 时的全局步长（节点参数优先，`outbound.rs`）；ADR-0069 | **已完成** |

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
| 出口存活判定 `outbound_connectivity_map` + `wan_outbound_is_alive` | `kern/tproxy.c:116`（1536 项）、`:2857-2885`（读函数）、`:3169,3605,3758`（三处判定）、`control/connectivity.go:13-18` | **已完成（v1.2）**：`outbound_connectivity_map`（1536）+ `outbound_is_alive`（保留 outbound/53 放行，按 domain×ipver 查表）+ BLOCKED_ALIVE 事件（限速键 = outbound）+ 控制面 2s 健康投影（`dial_mode=ip` 且策略非 random/fixed 且**组非空**）；内核级 `test-alive`（组标死→阻断→恢复）；ADR-0067；**v1.4 修实测缺陷**：投影改**全键域**（未被组覆盖的索引写 1，`main.rs:581-626`）+ 取图乐观初值（`:6843-6853`）——修掉「无 group 段配置下隐式 proxy 索引恒 0 → 新流首包被 SHOT」（devlog §22） | **已完成** |
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
| 代次/热重载/交接：`datapath_generation.go`、`fresh_datapath_state.go`、`generation_state.go`、`routing_epoch.go`、`routing_epoch_execution.go`、`routing_epoch_runtime.go`、`bpf_routing_epoch_attribution.go`、`control_plane_drain.go`、`control_plane_dialtarget.go`、`control_plane_dns.go` | `cmd/run.go:155-197`（`stagedReloadHandoff` 20+ 字段）、`run_reload.go:499`、`run_reload_worker.go:497` | **已完成（v1.5）**：drain 预算——`reload`/`suspend`/`resume --drain=N` 等旧代在飞会话自然排空的预算（`count_sessions`/`drain_old_generation`；超预算**不强制关闭**，如实回报余量与耗时；对照 dae `control_plane_drain.go`）；双 epoch 切槽（`main.rs:108-110`/`:3956-3964`）、reload 全流程与优雅退出（`:4189-4304`/`:6240-6258`）、`datapath_generation` 代次标记（v1.2，ADR-0067）之上补齐换代交接语义（ADR-0069） | **已完成** |
| 规则匹配与分流 VM：`routing_matcher_builder.go`、`routing_matcher_userspace.go`、`domain_routing_tracker.go`、`real_domain_runtime.go`、`hash_utils.go`、`utils.go`、`addr.go` | `component/routing/matcher_builder.go`；`control/routing_matcher_userspace.go` 头注释：「用户态重放规则」 | **已完成（v1.5）**：`real_domain_runtime`——新 `loader/src/real_domain.rs`（域名确认集 FIFO 8192 + 负缓存 300s + 单飞近似）+ `dns.rs::has_fresh_any_scope`（不限定 ECS 作用域，对照 dae `HasDnsKnowledge`）；`dial_mode=domain` 时 DNS 已知域名交节点远端解析，status 增 `real_domain` 段；`rules.rs`（数据面 VM 与用户态重放共用）、域位图投影/回收（`main.rs:7214-7279`）、sniff-punt 重判（`:3341-3357`）路径保留（ADR-0069） | **已完成** |
| TCP 流转发：`tcp.go`、`tcp_flow_binding.go`、`tcp_relay_core.go`、`tcp_relay_capabilities.go`、`tcp_relay_offload.go`、`tcp_copy_engine.go`、`tcp_copy_linux.go`、`tcp_copy_gather_linux.go`、`tcp_copy_other.go`、`tcp_copy_gather_other.go`、`tcp_sniff_policy.go` | `control/tcp.go`（relay 主体）、`tcp_copy_linux.go`（splice/copy 引擎） | `main.rs:3359-3773`（`handle_relay_conn`）、`:2523-2579`（copy pump）、`:2654-2731`（splice pump）、`reactor.rs`（epoll worker 池） | **已完成**（能力等价：splice 零拷贝、半关闭、SO_MARK 均实测，M1/M4） |
| TCP offload 生命周期：`tcp_offload_common.go`、`tcp_offload_hook.go`、`tcp_offload_links.go`、`tcp_offload_linux.go`、`tcp_offload_other.go` | `control/tcp_offload_hook.go`（fentry/kprobe 二选一）、`tcp_offload_links.go`（link 管理） | `main.rs:3070-3115`（try_offload）、`:2188-2260`（fentry/kprobe 挂载）、`:2867-2955`（看门狗）、`offload.rs`；**背压 fuse 已补（v1.2，ADR-0067）** | **已完成**（余：fuse 真实触发留生产观测） |
| UDP 会话与转发：`udp.go`、`udp_runtime.go`、`udp_flow.go`、`udp_flow_binding.go`、`udp_conn_state_tracker.go`、`udp_lifecycle.go`、`udp_profile.go` | `control/udp.go`、`udp_conn_state_tracker.go` | `main.rs:7372-7483`（`udp_nat_session`）、`:7540-7564`（janitor）、`:7297-7335`（会话读线程） | **已完成** |
| UDP 批处理/任务池：`udp_ingress_batch.go`、`udp_ingress_task.go`、`udp_task_pool.go`、`udp_write_batch.go` | `control/udp_ingress_batch.go`（recvmmsg 批量） | `main.rs:6556-6652`（`UdpRecvBatch` recvmmsg）、`:6438-6486`（`send_batch_to_udp` sendmmsg）；O7 四方对拍 20k pps 0 丢包 | **已完成**（已实测） |
| UDP endpoint pool / full-cone：`udp_endpoint_pool.go`、`udp_endpoint_lifecycle.go`、`udp_endpoint_reply.go`、`udp_endpoint_watcher.go` | `control/udp_endpoint_pool.go:20-27`（负缓存 `ErrEndpointFailed`）、`:29-40`（TTL/janitor） | **已完成（v1.4）**：full-cone 端点池（`UdpFlowKey{client, dst:Option}`，`main.rs:674-697`；`dst=None` = 同 client src 多目标复用一出口端点，上行按包 `send_to`、回包按上游真实来源注入）+ 分类 TTL（DNS 17s / QUIC·域名 300s / 代理地板 300s / NAT 默认，`:721-725`、`udp_ttl_secs :8871+`）+ 负缓存（`:667-680`）+ 1s janitor；内核级实测 `test-udp-cone`（双目标 4 报文复用 1 端点）；ADR-0068 | **已完成**（边界：full-cone 仅直连型出口；代理型仍 dest-affine——ADR-0068 偏离） |
| 原始 UDP 回退：`raw_udp_linux.go`、`raw_udp_other.go` | `control/raw_udp_linux.go:14-19`（65507 上限校验） | **已完成（v1.4）**：`raw_udp_send`（`main.rs:7419-7430`，AF_INET/AF_INET6 + SOCK_RAW + IPPROTO_UDP，65507 上限）+ 回包失败按 errno 判定回退（`raw_udp_eligible`/`raw_udp_send_all`，`:8826-8870`）+ `udp_nat.raw_udp_fallbacks` 计数 | **已完成** |
| DNS 控制面：`dns.go`、`dns_control.go`、`dns_cache.go`、`dns_control_optimistic.go`、`dns_controller_bpf.go`、`dns_controller_cache.go`、`dns_controller_forwarder.go`、`dns_controller_handle.go`、`dns_controller_response.go`、`dns_controller_runtime.go`、`dns_listener.go`、`dns_resolve.go`、`dns_runtime.go`、`dns_utils.go`、`dns_wire_ttl.go`、`runtime_dns_accounting.go` | `control/dns_controller_*.go` 全套（含 `dns_controller_bpf.go:17-24` 的 BPF 投影更新任务堆 + 重试） | **已完成（v1.5）**：BPF 投影重试堆——`publish_enqueue_retry`/`publish_retry_tick`（写失败退避重试 100ms→1.6s ×5、队列 4096；主循环 tick 消费），status 增 `domain_publish_retries`/`domain_publish_dropped`；`dns.rs`（缓存 27 项测试）、`dnsup.rs`（DoT/DoH/DoQ）、`dnsroute.rs`（请求/应答路由）、控制面解析/服务路径（`main.rs:6790-6988`/`:7081-7212`/`:7018-7077`；`dns.bind` 为 v1.4）保留（ADR-0069） | **已完成** |
| DNS 偏好等待：`dns_preference_wait.go` | `control/dns_preference_wait.go:16-26`（50ms）、`:63-137`（注册/通知） | **已完成（v1.5）**：见 §2——`loader/src/dns_pref_wait.rs` 50ms 偏好等待（非首选族缓存未命中、即将上行时登记；首选族到达即取消）；原「仅过滤」路径保留（ADR-0069） | **已完成** |
| 嗅探池：`packet_sniffer_pool.go` | `control/packet_sniffer_pool.go:17-22`（TTL 5s）、`:25-40`（会话表） | `sniffer.rs`（12 项测试）+ `quicsniff.rs`（QUIC Initial 解密） | **已完成** |
| 观测与事件：`runtime_stats.go`、`event_ringbuf.go`、`event_rate_contract.go`、`datapath_overflow_report.go`、`datapath_passthrough_report.go` | `runtime_stats.go:16-24`（1h 历史桶 + 250ms 采样）、`event_ringbuf.go`、`datapath_overflow_report.go` | **已完成（v1.5）**：1h 流量历史——`traffic_history_loop` 1s 采样写 status `traffic` 段（ring）+ 2 个 metrics；status JSON（`main.rs:8375+`）、Prometheus 文本（`:8630-8921`）、事件消费（`:1099-1136`）、overflow 清扫与事件上报（`:4370-4396`）、事件限速键域对齐（v1.2，0..261）保留（ADR-0069） | **已完成** |
| 告警节流：`alert_pacing.go` | `control/alert_pacing.go:14-22`（「持续条件合并为 N 秒一条 + 上报观察次数」） | **已完成（v1.5）**：`AlertPacer`（持续条件 + 观察次数 + 冷却窗口；接入 redirect_track 容量告警（60s，对照 dae `mapCapacityAlertCooldown`）与 conn_state 容量告警）+ 事件按类型限速保留（ADR-0069） | **已完成** |
| 钩子生命周期：`tc_hook_set.go`、`tc_hook_handoff.go` | `control/tc_hook_set.go`、`tc_hook_handoff.go`（跨代钩子交接） | **已完成（v1.5）**：lab `test-hooks` 用例（`lab.sh`：reload 切代前后 hooks 集合不变——单进程形态钩子常驻、无跨代交接/无重复挂载，把 ADR-0065 的「形态消解」结论落成可检验断言）+ 既有挂载/自动摘链（ADR-0069） | **已完成** |
| 状态清扫与 pinning：`conn_state_janitor.go`、`conn_state_pinning.go` | `conn_state_janitor.go:197-199`（含 routing_handoff 清扫，60s 级） | `main.rs:4370-4396`（conn_state）、`:4403-4442`（redirect_track）；**map pinning 已补（v1.2，见 §3）** | **已完成** |
| 拨号/健康/连接性：`dial.go`、`connectivity.go`、`node_latency.go` | `dial.go`（拨号参数与 must 语义）、`connectivity.go:13-18`（3 域 × 2 IP 版本 × 出口）、`node_latency.go:12-19`（延迟快照 API） | `group.rs`（探测/策略/`min_moving_avg`/容忍度/UDP DNS 探测）、`main.rs:3021-3039`（按组选 dialer）；**数据面连通性投影已补（v1.2，ADR-0067：`outbound_connectivity_map` + 2s 健康投影）** | **已完成** |
| 会话管理与 abort：`session_manager.go` | `control/session_manager.go:143-151`（进程级 flow owner）、`cmd/reload.go:260`（`--abort`）、`cmd/run.go:164,795,835`（交接时 abort） | **已完成（v1.4）**：代次化会话登记（TCP relay/reactor/UDP NAT 会话带 `generation`）+ `reload/suspend --abort`（`main.rs:9174-9250`、`:10972-10982`；`AbortScope::OldGeneration|All`，顺带 conn_state scrub） | **已完成**（边界：QUIC 系协议无底层 socket，abort 置 stop 位由 pump 自行退出——ADR-0068 偏离） |
| 系统集成：`netns_utils.go`、`sysctl.go` | `control/netns_utils.go`（建 netns/移网卡/tproxy 规则）、`sysctl.go:32`（`InitSysctlManager` + fsnotify 监视回写） | **已完成（v1.5）**：新 `loader/src/sysctl.rs`——写 `ip_forward`/`forwarding`/`send_redirects`/`accept_ra` **并登记期望值**，inotify 监听（降级 2s 轮询），**运行中被改回即纠正**（对照 dae `SetForwarding`/`SetSendRedirects`）；脚本侧等价（`lab/gateway.sh`）保留（ADR-0069） | **已完成** |
| netkit 设备（替代 veth） | `control/netkit_linux.go:11-25`（`NetkitConfig`，含 `ScrubNone` 关 mark 擦除）、`netkit_netlink.go` | **已完成（v1.4，lab 侧）**：`make_control_pair`（`lab/lab.sh:376-396`：`ip link add ... type netkit mode l2 scrub none`，**一次性创建成功**才用、否则回退 veth；`mode l2` 是硬要求——内核默认 l3 无 MAC 会破坏以太/NDP 数据面）；QEMU 7.2.8 实测打出「控制面对: netkit（mode l2 + scrub none）」 | **已完成**（余：`lab/gateway.sh` 生产网关脚本仍用 veth） |
| 跨代资源租约：`egress_runtime.go`、`listener_runtime.go` | `egress_runtime.go:14-20`（出口租约引用计数）、`listener_runtime.go:8-14`（listener fd 跨代交接） | 无 | **已完成**（形态消解：sodama 单进程常驻 listener，reload 不重建 listener/不换代出口对象，此类交接问题不存在） |
| UDP GSO 批量发送：`anyfrom_pool.go` | `control/anyfrom_pool.go:29-40`（GSO 支持 + TTL 刷新节流 200ms） | **已完成（v1.5）**：`udp_gso_enable`/`send_gso_udp`——`UDP_SEGMENT` cmsg 聚合（≤64 段；EMGSIZE/EINVAL/EOPNOTSUPP 回落逐包发送）+ status `gso_sends`/`gso_datagrams`/`gso_unsupported`；sendmmsg 批量路径保留（ADR-0069） | **已完成** |
| 多对象集维护：`datapath_janitor.go` | `control/datapath_janitor.go:17-25`（「one ringbuf reader for one BPF object set」） | `main.rs:1099-1136`（单对象集消费线程） | **已完成**（sodama 只有一套对象集，不需要多读者） |

---

## 5. 运维/发布面

对照对象：`dae/install/`、`dae/.github/workflows/`、`dae/Dockerfile`、`dae/Makefile`、`dae/hack/` vs 本仓库 `install/`、`sodama/lab/`、`.github/workflows/`、`docs/deploy.md`、`docs/openwrt.md`。

| 能力/项 | dae 证据（文件:行号） | sodama 现状（文件:行号 或「无」） | 判定 |
|---|---|---|---|
| systemd 单元 | `dae/install/dae.service:7-8`（崩溃环熔断）、`:11`（Type=notify）、`:25`（OOMScoreAdjust=-100）、`:40-42`（ExecStartPre validate / ExecStart / ExecReload） | **已完成（v1.5）**：`install/sodama.service`——`Type=notify`（`main.rs::sd_notify`：READY/RELOADING/STOPPING；无 `NOTIFY_SOCKET` 时 no-op）+ `ExecStartPre` validate 门禁 + `StartLimitIntervalSec=300`/`StartLimitBurst=5` + `OOMScoreAdjust=-100` + `Restart=on-abnormal` + `TimeoutStartSec=120`/`TimeoutStopSec=30` + `LimitNPROC=4096`（ADR-0069） | **已完成** |
| 安装/卸载脚本 | `dae/install/package_after_install.sh`、`package_after_remove.sh`（发行包钩子） | `install/install.sh:1-232`（`--build/--no-build/--dry-run/--uninstall`，`:131-134` systemd 集成） | **部分**：安装/卸载/干跑已有；缺升级与失败回滚（`backlog.md:34` A9） |
| shell 补全 | `dae/install/shell-completion/{dae.bash,dae.zsh,dae.fish}` | **已完成（v1.4）**：`install/shell-completion/sodama.{bash,zsh,fish}`（与 `sodama completion` 子命令同源）+ `install/install.sh` 部署（补全目录自动探测） | **已完成** |
| 容器镜像 + compose | `dae/Dockerfile:1-37`（多阶段 + geo 数据校验）、`dae/docker-compose.yml:1-11`（privileged/host net/pid） | 无（`panel/deploy` 是面板自身部署，不含引擎镜像） | **未做** |
| 发行工件与发行 CI | `dae/.github/workflows/release.yml:2,319-341`（tag 触发 + GH Release）、`prerelease.yml`、`daily-build.yml`、`nightly.yml` | 无（`.github/workflows/` 只有 `ci.yml`） | **未做** |
| 内核参数/前提文档 | `dae/docs/zh/user-guide/kernel-parameters.md:19-60`（sysctl 清单） | `docs/openwrt.md`（kernel fragment 18 项，`:35` NAMESPACES 硬前提）+ `docs/deploy.md:115-132`（sysctl 与恢复）+ `install/openwrt/kernel-fragment.config` | **已完成** |
| OpenWrt 打包（musl 交叉构建 + ipk/procd/uci） | dae 无（未见 OpenWrt 打包；证据：`find dae -iname '*openwrt*'` 空） | `install/openwrt/{Makefile,sodama.init,sodama.config,sodama-datapath,README.md}` + `lab/build-openwrt.sh` + `lab/openwrt-smoke.sh` + `docs/openwrt.md` | **已完成**（sodama 独有） |
| 一键网关脚本（含启动自检与失败回滚） | dae 无（依赖发行版网络管理） | `sodama/lab/gateway.sh`（`up/down`、sysctl 保存恢复、就绪才返回；ADR-0029，已实测） | **已完成**（sodama 独有） |
| 部署/使用文档 | `dae/docs/zh/user-guide/run-as-daemon.md`、`tutorials/{run-on-alpine,run-on-centos7,run-on-macos,dae-with-opnsense}.md` | `docs/deploy.md`（305 行）+ `docs/openwrt.md`（172 行） | **部分**：缺面向最终用户的多发行版教程（dae 的 macOS 教程对本项目不适用，见「不适用」） |
| 配置文档自动生成 | `dae/hack/ci/config-doc-generator.py`（由 config 结构生成 `docs/configuration/*`） | **已完成（v1.4）**：`sodama config-doc [--format md\|json] [--out <file>]`（`main.rs:9747-9800`，从 `config.rs` 的 `key_docs()` 登记表生成）+ 产物 `docs/config-reference.md` + drift 单测 `config_doc_registry_covers_all_keys`（登记表/键域漂移即红） | **已完成** |
| 配置参考与迁移指南 | `dae/docs/{en,zh}/configuration/{routing,dns,separate-config,gaming-oriented-routing,external-dns}.md` | **配置参考部分已完成（v1.4）**：独立参考 `docs/config-reference.md`（`config-doc` 生成 + drift 单测锁定）；迁移指南未单独立文（散见 `sodama/README.md`/`docs/deploy.md`） | **部分**（余：迁移指南单独立文） |
| 版本与 CHANGELOG | `dae/CHANGELOGS.md`（90KB，自动生成 `generate-changelogs.yml`）、`dae/Makefile:90`（版本注入 ldflags） | `Cargo.toml` 0.1.0，无 CHANGELOG（`backlog.md:29` A4） | **未做** |

---

## 6. 工程化/质量面

对照对象：`dae/*_test.go` 布局、`dae/fuzz` 类目标、`dae/control/kern/tests/`、`dae/.github/workflows/` vs sodama 的 `#[test]` 矩阵、`sodama/lab/`、`lab/matrix/`、CI。

| 能力/项 | dae 证据（文件:行号） | sodama 现状（文件:行号 或「无」） | 判定 |
|---|---|---|---|
| 单元测试规模 | 244 个 `*_test.go` / 39,453 行（`find dae -name '*_test.go' \| wc -l`） | **已完成（v1.5）**：**346 + 3 `ebpf-logic` = 349 通过**（`cargo test --release` 实测；较 v1.4 的 329 +20） | **已完成**（口径仍不可直接比——文件数 vs 用例数；ADR-0069） |
| 数据面（BPF）单测 | `dae/control/kern/tests/{bpf_test.c,tcp_offload_header_test.c}` + `dae/Makefile:200-211`（`make ebpf-test` 用 `test_runtime` 在用户态跑 C 数据面逻辑） | **已完成（v1.4）**：纯逻辑抽到 host 可测 crate `sodama/ebpf-logic`（`ebpf-logic/src/lib.rs`，3 项：SYN 新流判定/IPv4 头长与分片尾/限速窗口），数据面与测试**同源函数**引用（不复制） | **已完成**（余：eBPF 本体仍由 lab 集成用例覆盖） |
| fuzz 目标 | 7 个：`cmd/runtime_supervisor_fuzz_test.go`、`component/sniffing/{quic,http,tls}_fuzz_test.go`、`sniffing/internal/quicutils/cipher_fuzz_test.go`、`control/{tcp_dns_frame,dns_cache}_fuzz_test.go` | **已完成（v1.4，确定性形态）**：`loader/src/fuzz_smoke.rs`（固定种子 xorshift 变异器 + 真实语料种子；覆盖 .dae 配置含 include/DNS 报文/出站链接全家族/订阅含 SIP008/TLS CH/QUIC Initial/HPACK-QPACK；2 项测试、`SODAMA_FUZZ_ITERS` 可调，默认 4000 轮 ≈1-2s）；**不走 libFuzzer/cargo-fuzz**（不可复现工具链，ADR-0068） | **已完成**（口径差异：确定性变异测试 vs libFuzzer 目标） |
| 规则编译对拍 | dae 自身即基准 | `lab/parity.sh:1-40`（Go 侧 `lab/parity/run.sh` + Rust 侧 `--compile-dump`，5 个规则文件逐字节 diff） | **已完成**（sodama 独有，已实测） |
| netns 集成用例 | dae：仅有**带 mock 的 netns 作用域单测**（`dae/cmd/listener_netns_test.go:16-30` 打粧 `withDaeNetnsRequiredFunc`，不建真实 netns）；无真实 netns 拓扑夹具（未找到） | `lab/lab.sh`（4227 行，74 个 `test-*` 目标）、`lab/gateway.sh`、`lab/real-node-e2e.sh`、`lab/soak.sh` | **已完成**（sodama 独有，已实测） |
| 内核矩阵 | `dae/.github/workflows/kernel-test.yml:39-95`（CI 内多架构/内核构建与测试） | `lab/matrix.sh` + `lab/matrix/SUMMARY.md`（宿主 6.18.54-lts 9/9；QEMU 7.2.8 `verify` 12/12 + `cap` 12/12（v1.5 含新增 `test-hooks`；`offload=` 为信息项——QEMU 既有抖动），含 `l3-attach`/`xdp` 入门禁） | **部分**：矩阵有且更贴近数据面，但**不入 CI**（需 root/特权） |
| CI 覆盖 | 17 个 workflow（build/go-test+race+vet/bpf-test/kernel-test/lint/docker/release/prerelease/nightly/daily-build/ebpf-audit/check-docs/sync-docs/...） | `.github/workflows/ci.yml`（1 个：eBPF 对象构建 + loader 编译 + 单测 + **lint 门禁（v1.4：fmt --check + clippy -D warnings）**；显式声明不做特权加载） | **部分**：lint 已补；余特权内核加载、容器/发行流水线 |
| 静态检查/lint 门禁 | `dae/.golangci.yml`、`.github/workflows/lint.yml`、`.pre-commit-config.yaml` | **已完成（v1.4）**：`ci.yml:106-120`（`cargo fmt --check` + `cargo clippy --workspace --all-targets --locked -- -D warnings`）+ 放行清单 `sodama/Cargo.toml [workspace.lints.clippy]`（逐条附理由）；本地清零 | **已完成** |
| 长稳/soak | `dae/scripts/control-memory-profile.sh`（内存剖面工具） | `lab/soak.sh`、`lab/perf/soak-curve.sh`（35/60min 曲线，RSS +3.1%）；72h 进行中（`docs/README.md:41,106`、`backlog.md:111`） | **部分**：脚本与判据齐备、短时可判；72h 未完成且不入 CI |
| 性能对拍 | dae 无 in-tree 基准对拍（`dae/scripts/` 无 bench） | `lab/perf/{run,scaling,udp,real,mem,mem-system,m2ab,codec-stress,soak-curve}.sh` + `lab/perf/gen-benchmark-report.py`（四方对拍 + 真实节点 `real.sh`） | **已完成**（sodama 独有，已实测） |
| 依赖/供应链审计 | `dae/.github/workflows/ebpf-audit.yml` + `dae/scripts/ebpf-audit.sh`、`.pre-commit-config.yaml` | **部分**：`docs/security-proposal.md` S0–S5 仍待采纳；其中「fuzz 目标」已以确定性形态落地（v1.4，见上）；余 QEMU 特权加载入 CI、cargo-deny 等 | **部分** |

---

## 不适用 / 已评估否决

| 项 | dae 证据 | 不列入缺口的理由 |
|---|---|---|
| `dae honk`（彩蛋命令） | `dae/cmd/honk.go:17-29` | 无功能意义，不构成能力 |
| `dae completion` 的**补全内容**归入 §5（v1.4 已补）；但 cobra 自动补全机制本身 | `dae/cmd/completion.go:16-33` | 已在 §5 记为「已完成（v1.4）」，此处不重复计数 |
| `internal.AutoSu()` 自动 sudo 提权 | `dae/cmd/internal/su.go:1-60`、`dae/cmd/run.go:236-242`、`--disable-sudo`（`run.go:214`） | sodama 定位为 systemd/脚本托管的网关（`install/sodama.service`），提权由服务管理器负责；容器/OpenWrt procd 场景下自动 sudo 反而有害 |
| `dae-ebpf-audit`、`gen_ebpf_sync` 开发者工具 | `dae/cmd/dae-ebpf-audit/main.go`、`dae/cmd/generators/gen_ebpf_sync/` | C→Go 生成链路的开发工具，C 数据面已退役（ADR-0025），无对应物 |
| daed Web UI / GraphQL / 鉴权 / `component/daedns` | `dae/component/daedns/{client,router}.go` | 独立项目（daemon）；sodama 的等价形态是自研 `panel/`（`docs/backlog.md:118` 明示永久不在范围） |
| `unused_lpm_type` map | `dae/control/kern/tproxy.c:312` | C 侧类型占位（注释即表明未使用），无功能 |
| 上游已废弃配置键 `enable_local_tcp_fast_redirect`、`auto_config_firewall_rule` | `dae/config/config.go:38-42`（Deprecated 注释） | dae 自身已不消费；sodama 允许键但同样不消费，行为一致 |
| macOS / Windows 支持 | `dae/docs/zh/tutorials/run-on-macos.md` | 数据面依赖 Linux eBPF（`docs/backlog.md:120` 永久不在范围） |
| 发行版打包配方（AUR/PKGBUILD/deb/rpm） | dae 仓库内**未找到** in-tree 配方（`dae/install/` 只有包管理器**钩子**，`package_after_*.sh`） | dae 上游 in-tree 无配方，故不构成「dae 有我们没有」的对标缺口；仅作为 `backlog.md:32` A7 的自选项 |
| `dae/sysdump` 的 netfilter/iptables 抓取中的**规则下发**能力 | `dae/cmd/sysdump.go:260-277` | dae 只**读取**现场（不写规则），sodama 数据面不依赖 nft/iptables（`docs/openwrt.md:123`）；取证内容已于 v1.5 补齐（`sysdump --out`），此处不构成能力缺口 |
| `tproxy_port_protect` | `dae/config/config.go:21` → `control_plane.go:878`，C 未读（`kern/tproxy.c:215`） | 上游空置功能，两端一致（详见 §2） |

---

## 汇总表

| 维度 | 行数 | 未做 | 部分 | 已完成 |
|---|---|---|---|---|
| 1. CLI 面 | 18 | 0 | 0 | 18 |
| 2. 配置面 | 21 | 0 | 0 | 21 |
| 3. 数据面 | 24 | 0 | 0 | 24 |
| 4. 控制面子系统 | 24 | 0 | 0 | 24 |
| 5. 运维/发布面 | 12 | 3 | 3 | 6 |
| 6. 工程化/质量面 | 11 | 0 | 4 | 7 |
| **合计** | **110** | **3** | **7** | **100** |

（表内每行判定均为三档之一；判定为「不适用」的项一律只在上一小节列出，不计入本表。
v1.1（2026-10-16 晚）：能力缺口批次 #1–#4 落地，4 行由「未做/部分」转「已完成」——§2 两行（must 糖、订阅 `-file` scheme）、§3 一行（`routing_map` 容量）、§4 一行（接口懒绑定/热插拔）。
v1.2（2026-10-16 深夜）：**eBPF 余项批次落地，§3 数据面 24 行全部「已完成」**——4 项未做（`lan_egress`/出口存活/背压 fuse/pinning）与 6 项部分（事件 3/5/9/限速键域/容量可配/stats 键/handoff）全部补齐（ADR-0067、devlog §21）；残留项为已文档化的偏离（per-CPU 限速、运行期容量、pinning 迁移方案等，见 ADR-0067 偏离清单）。
v1.3（2026-10-16）：引用回填与清单固化——§4 两行随 §3 同步转「已完成」（offload 生命周期、拨号/健康/连接性），§2 global 生效面更新（生效 23 → **26**：`lan_interface`/`wan_interface`、`bpf_conn_state_map_size`；不生效 22 → 19）；新增**附 A · 当前能力缺失清单**（未做 20 + 部分 28 的过滤视图，随本表同步维护）。
v1.4（2026-10-16）：**A1 批次（除工程打包）落地 17 项**（ADR-0068、devlog §22）——未做 20 → **3**（全部为发布工程）；部分 28 → **26**（§2 global 生效面 18 项、§4/§5/§6 各行随表；原 #24–#28 中 abort/配置参考/fuzz 等转已完成）；数据面 24 行仍全「已完成」，但补录一处**实测缺陷修复**（全键域投影，见 §3 行内）。
v1.5（2026-10-16）：**A2 批次（除工程打包）落地 19 项**（ADR-0069、devlog §23）——部分 26 → **7**（全部工程打包类；§1 CLI 五件套、§2 global 生效面、§4 九行、§5 systemd、§6 单测口径随表转「已完成」）；global 生效面 27 → **36**（不生效 18 → 9，余项均有显式告警或 ADR 记录）；单测 329 → **346 + 3（`ebpf-logic`）= 349**；内核级 QEMU 7.2.8 `verify` 12/12 + `cap` 12/12（新增 `test-hooks`；`offload=` 为既有抖动信息项，非本批引入）。）

读数提示：

- **「部分」占 7/110（v1.5）**——这是本次收口的标志：sodama 的缺口形态原以「能力在但语义/覆盖/形态不完整」为主，A2 批次后**能力类「部分」清零**（§1/§2/§3/§4 全部「已完成」），剩余 7 项全部为工程打包类（见附 A）；「未做」仅剩 A1 的 3 项发布工程。
- **§4 的 24 项（v1.5 起）全部「已完成」**——15 项是形态消解（跨代租约、多对象集、单进程 listener 等），9 项由 A2 批次补齐（drain 预算、`real_domain_runtime`、DNS 投影重试堆、1h 观测、告警节流、钩子用例、sysctl 纠正、UDP GSO 等，ADR-0069）；该维度此前「部分」偏高是因为按机制簇切分容易「主链路等价 + 边缘语义缺一项」，本批把边缘语义收口。

---

## 我最有把握的 top 10 缺口

排序口径：**对「日常代理网关」的影响**（用户可感知 + 静默程度 + 触发概率）优先于工程化完备度。触发概率低或只在特定拓扑下出现的排后面。

| # | 缺口 | 为什么排这里 |
|---|---|---|
| 1 | ~~`must_<组名>` 前缀糖未实现且**静默映射为 proxy**（§2）~~ **✅ 已完成（本批 #1，ADR-0066、devlog §20；内核级实测 `test-must`）** | 唯一一条「写错了不报错、且给出错误语义」的缺口：配置里写 `must_proxy` 的流量会被当成 `proxy` 处理，DNS 也会被劫持处理（正是 `must` 想避免的）。它不以「配置错误」形式出现——只在 `validate`/启动日志的 outbound 映射行里能看到 `must_x -> proxy`（`main.rs:3875`，由 `config.rs:1719-1726` 的兜底分支产生），容易被当成正常路径。 |
| 2 | ~~订阅节点缓存**不落盘**（`https-file://` 语法 + `persist.d` 语义缺失，§2）~~ **✅ 已完成（本批 #2，ADR-0066；内核级实测 `test-sub-file`）** | 路由器重启 + 订阅源不可达 = 零节点启动。sodama 已有同类生产事故记录（`subscribe.rs:60` 注释：「生产实测：15:35 双源截断 → dialer=none」；另见 `parity-status.md:57`），而当前兜底只有**内存**缓存（重启即失，`main.rs:4646-4694`）与 `fetch_lenient`。日常网关的**可用性单点**。 |
| 3 | ~~接口懒绑定 / 热插拔缺失（`wan_interface: auto`、glob pattern、netlink add/remove 回调，§4）~~ **✅ 已完成（本批 #3，ADR-0066；内核级实测 `test-hotplug`；实现为 1s 轮询而非 netlink）** | 网关形态下设备变动是常态（USB 网卡、容器 veth、接口改名、拨号重建）。dae 在接口出现时自动补挂（`interface_manager.go:38-50` + `control_plane_core_bind.go:487+`），sodama 只在启动时按**精确名字**挂一次；变动后该接口流量**静默不被接管**。 |
| 4 | ~~`routing_map` 上限 64 vs 1024（§3）~~ **✅ 已完成（本批 #4，ADR-0066；`bpf_loop` 路线，内核级实测 `test-rules-cap`）** | 直接决定「大规则集能不能上线」：sodama 编译期报错拒启（不静默，但配置改不动）。参考点：`dae/example.dae:370-394` 的 routing 段只有 6 条规则，远低于上限——**推断**（未统计社区配置样本）：风险只在「规则数 > 64」的大配置上变现（如逐站点 `domain()` 白名单 + `pname` 组合），届时为硬门槛。 |
| 5 | ~~TLS 分片与 uTLS 指纹开关全部不生效（`tls_fragment*`/`utls_imitate`/`tls_implementation`，§2）~~ **✅ 已完成（v1.5，ADR-0069、devlog §23；分片仅自实现 TLS 路径生效——偏离 2）** | 直接影响「能不能过」：SNI 分片是抗阻断的常用手段，且 dae 是全局开关一次生效。sodama 有自实现 Chrome-120 指纹（REALITY 路径），但**用户无法切换/分片**，也无法对普通 TLS 出站生效。 |
| 6 | ~~数据面「出口已死」判定缺失（`outbound_connectivity_map` + `wan_outbound_is_alive`，§3）~~ **✅ 已完成（eBPF 余项批次，ADR-0067，devlog §21；内核级实测 `test-alive`：组标死→数据面阻断→恢复）** | 出口全死时 sodama 仍把流量 redirect 到控制面，靠 relay 侧拨号失败兑底：每一次失败都要走完整 tproxy→relay→dial 链路，表现为**延迟上升与失败率放大**，而不是数据面直接丢弃/回退。 |
| 7 | ~~global 生效面缺口里的「日常行为参数」：`fallback_resolver`、`allow_insecure`、`log_level`、`so_mark_from_dae`、`disable_thp`、`pprof_port`、`bandwidth_max_*`（§2）~~ **✅ 已完成（v1.5，ADR-0069、devlog §23）** | 这些是**运维/排障日常**要用的旋钮：`log_level` 决定能否临时提详细度；`fallback_resolver` 决定节点域名解析的兜底；`allow_insecure` 是全局兜底（节点级已有）；`pprof_port` 决定能不能现场抓火焰图。逐项影响不大，但合起来是「调不动」的观感。 |
| 8 | ~~reload/suspend 不带 `--abort`，且无 session_manager（§1/§4）~~ **✅ 已完成（v1.4，ADR-0068、devlog §22）** | 换节点或改配置后，**已建连接继续走旧出口**直到自然结束（长连接可能是小时级）。对「改完立刻生效」的预期是直接违背。 |
| 9 | ~~`conn_state_map` 容量 65536（dae 默认 262144）且**不可配**、无 pinning（§3）~~ **✅ 已完成（eBPF 余项批次，ADR-0067：默认 262144 + `bpf_conn_state_map_size` 启动生效 + pinning/冷启动迁移；内核级实测 `test-pinning`）** | 高并发网关（数万 flow）下提前触发溢出路径（有事件与计数，非静默），且重启后既有流状态全失（靠无状态放行兑底）。属于**容量安全边际**问题。 |
| 10 | ~~运维日常三件套：日志轮转三参缺失、无 pidfile、无 `--version`/`completion`（§1/§5）~~ **✅ 已完成（v1.5，ADR-0069——轮转三参含压缩；pidfile/`completion` 系 v1.4，ADR-0068）** | 路由器上最现实的故障是**磁盘被日志吃满**（sodama 只有 SIGHUP reopen，需用户自配 logrotate）；pidfile/`--version`/补全是脚本化运维与工单取证的最低要求。 |

紧随其后（第 11–15，未进 top 10）：~~UDP endpoint pool/full-cone 与 raw UDP 回退~~、~~订阅 SIP008 + 链式代理 `chains`~~、~~`dns.bind` 明文 DNS 监听出口~~、~~lint 门禁/数据面单测/fuzz~~——**v1.4 A1 批次已全部落地（ADR-0068，devlog §22）**；**v1.5 A2 批次再收口运维取证与全部能力余项（ADR-0069，devlog §23）——top 10 至此全部清零**，剩余**发布/工程打包 10 项**（A1 未做 3 + A2 部分 7：容器镜像/发行工件与发行 CI/版本与 CHANGELOG/安装升级回滚/多发行版教程/迁移指南/内核矩阵入 CI/CI 容器流水线/72h soak/供应链审计——见附 A）。`tcp_offload_pause` 背压 fuse 已随 eBPF 余项批次落地（ADR-0067），自本条移出。

> **v1.5 注**：top 10 中 #1–#4（v1.1，ADR-0066）、#6 与 #9（v1.2，ADR-0067）、#8（v1.4，ADR-0068）、#5/#7/#10（v1.5，ADR-0069，devlog §23）已全部落地；剩余缺口的完整过滤视图见**附 A**（未做 3 + 部分 7，全部为工程打包类），它随汇总表同步维护，是“当前还缺什么”的单一入口。

**排序理由摘要**：前 4 名都是「会让用户直接感知或静默出错」的项（语义错、启不来、不接管、上不了线）——**v1.1：这 4 项已全部落地并内核级实测**（ADR-0066、`phase2-devlog.md` §20）；5–9 名是「能不能过 / 过得好不好 / 出问题能不能查」的项；第 10 名是把若干小项合并的运维基线缺口。数据面形态类（netkit、GSO、scratch map）与纯工程化类（CI 矩阵、打包）按此口径全部后置。

---

## 附 A · 当前能力缺失清单（v1.5 快照：未做 3 + 部分 7 = 10 项）

> **单一入口**：只列「未做」与「部分」（已完成/不适用见上文各表）；本清单随汇总表同步维护。
> 判定口径与逐条证据（dae 文件:行号 ↔ sodama 现状）见对应小节；「部分」列中的一句即「缺什么」。

### A1 · 未做（3 项，全部为发布/工程打包类）

> **v1.4（A1 批次，除工程打包）已落地 17 项**（ADR-0068、`phase2-devlog.md` §22，逐项证据见上方各表同步行）：原 #1 `--disable-timestamp`、#2 pid 文件、#3 `completion` 子命令、#4 `dns.bind`、#5 group 级 `tcp_check_http_method`、#6 `chains` 链式代理、#7 SIP008、#8 `check_interval>0` 校验、#9 UDP 端点池/full-cone、#10 raw_udp 回退、#11 会话管理与 abort、#12 netkit（lab 侧）、#13 shell 补全工件、#16 配置文档生成、#18 BPF 单测（`ebpf-logic`）、#19 确定性 fuzz、#20 lint 门禁。内核级验收：QEMU 7.2.8 `verify` 12/12 + **cap 11/11**；单测 **326 + 3 = 329 通过**。

| # | 域 | 项 | 缺什么（一句） |
|---|---|---|---|
| 1 | 运维 | 容器镜像 + compose | 无引擎镜像（panel/deploy 不含引擎） |
| 2 | 运维 | 发行工件与发行 CI | 无 tag 发行/prerelease/nightly 流水线 |
| 3 | 运维 | 版本与 CHANGELOG | `Cargo.toml` 0.1.0，无 CHANGELOG/版本注入 |

### A2 · 部分（7 项，全部为工程打包类）

> **v1.5（A2 批次，除工程打包）已落地 19 项**（ADR-0069、`phase2-devlog.md` §23，逐项证据见上方各表同步行）：原 #1 `--version`、#2 日志轮转三参、#3 `trace` 过滤器、#4 `sysdump` 网络现场、#5 `export outline`、#6 global 生效面（生效 27 → 36、不生效 18 → 9）、#7 `dns.ipversion_prefer` 偏好等待、#8 `global.udphop_interval`、#9 代次/热重载交接（drain 预算）、#10 `real_domain_runtime`、#11 DNS 投影重试堆、#12 DNS 偏好等待（同 #7）、#13 观测 1h 流量历史、#14 告警节流、#15 钩子生命周期、#16 系统集成（sysctl 被改回即纠正）、#17 UDP GSO、#18 systemd 单元、#22 单测口径。内核级验收：QEMU 7.2.8 `verify` 12/12 + `cap` 12/12（含本批新增 `test-hooks`；`offload=` 为既有 QEMU 抖动信息项，非本批引入）；单测 **346 + 3（`ebpf-logic`）= 349 通过**。

保留的 7 行为 v1.4 原编号 #19–#21、#23–#26（本版重编号 #1–#7）：

| # | 域 | 项 | 缺什么（一句） |
|---|---|---|---|
| 1 | 运维 | 安装/卸载脚本（原 #19） | 缺升级与失败回滚 |
| 2 | 运维 | 部署/使用文档（原 #20） | 缺多发行版教程（面向最终用户） |
| 3 | 运维 | 配置参考与迁移指南（原 #21） | 配置参考已生成（v1.4：`docs/config-reference.md` + drift 单测）；余迁移指南单独立文 |
| 4 | 工程 | 内核矩阵（原 #23） | 有且更贴近数据面，但**不入 CI**（需 root/特权） |
| 5 | 工程 | CI 覆盖（原 #24） | lint 门禁已补（v1.4）；余特权内核加载/数据面对象验证/容器流水线 |
| 6 | 工程 | 长稳/soak（原 #25） | 脚本与判据齐备；72h 未完成且不入 CI |
| 7 | 工程 | 依赖/供应链审计（原 #26） | fuzz 目标已以确定性形态落地（v1.4，见 §6）；余 cargo-deny 等（`security-proposal` S0–S5 待采纳） |

### 排序建议（“下一批做什么”，v1.5 重排）

1. **工程打包总收尾**（A1 未做 3 项 + A2 部分 7 项，共 10 项，已无能力类缺口）——容器镜像 + 发行工件与发行 CI + 版本与 CHANGELOG（A1）与安装升级回滚、多发行版教程、迁移指南、内核矩阵入 CI、CI 容器流水线、72h soak、供应链审计（A2）可合并为一条「从可运行到可分发」的流水线推进；
2. **偏离清单的观测驱动收口**（ADR-0069 偏离 1–6：`trace` 事件环丢尾帧、`tls_fragment*` 的 rustls 路径、`bandwidth_max_*` 限额时的拷贝泵性能回归评估、`wait_for_network` 无事件源等）——无用户可感知缺口，按生产观测决定是否投入；
3. **9 个「解析但不生效」键**（`tproxy_port`/`tls_fragment*`/`utls_imitate`/`tls_implementation`/`pprof_port`/`bandwidth_max_*`）——维持现「显式告警/ADR 记录」语义，随上游语义变化再评估；
4. 其余（生产观测：背压 fuse 真实触发、`offload=` QEMU 抖动定位、pinning 迁移方案等 ADR 已记录边界）在真实需求触发时再做。
