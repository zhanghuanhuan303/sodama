# sodama 配置参考（自动生成，不要手工编辑）

由 `sodama config-doc` 从 `loader/src/config.rs` 的 `key_docs()` 生成；修改请改登记表并重新生成（`cargo test` 的 drift 用例会锁定同步）。

「生效」列：✅ = 键有消费点；⚠️ = 解析通过但当前无消费点——不把解析写成生效（口径见 `docs/capability-gap-review.md` §2）。

## global

| 键 | 说明 | 默认 | 生效 |
|---|---|---|---|
| `tproxy_port` | tproxy 监听端口（实际仅 CLI `--tproxy-port` 生效） | `12345` | ⚠️ 无消费点 |
| `tproxy_port_protect` | 保护 tproxy 端口的防火墙标记（dae 与本实现两端均为空置字段） | `0x8000000` | ⚠️ 无消费点 |
| `so_mark_from_dae` | 控制面自身 socket 的 SO_MARK（数据面按同值跳过自环） | `0x233` | ✅ |
| `log_level` | 日志级别（off/error/warning/info/debug；默认 info） | `info` | ✅ |
| `tcp_check_url` | 组健康检查目标（tcp） | `http://cp.cloudflare.com` | ✅ |
| `tcp_check_http_method` | 探测 HTTP 方法（大写白名单；非法回退 CONNECT） | `HEAD` | ✅ |
| `udp_check_dns` | 组健康检查目标（udp DNS） | `dns.google:53, 8.8.8.8:53` | ✅ |
| `check_interval` | 健康探测周期（必须为正） | `30s` | ✅ |
| `check_tolerance` | 连续失败容忍次数 | `1` | ✅ |
| `lan_interface` | LAN 接口（逗号分隔；支持 glob/auto） | `landae（CLI 默认）` | ✅ |
| `wan_interface` | WAN 接口（逗号分隔；auto = 默认路由接口；1s 轮询热插拔） | `wan（CLI 默认）` | ✅ |
| `allow_insecure` | 跳过 TLS 证书验证（全局默认；节点参数优先） | `false` | ✅ |
| `dial_mode` | 拨号模式 ip|domain|domain+|domain++ | `ip` | ✅ |
| `disable_waiting_network` | 启动时不等待网络就绪（默认会等到默认路由+DNS 可达或超时 30s） | `false` | ✅ |
| `disable_thp` | 本进程退出透明大页（PR_SET_THP_DISABLE；不改系统全局） | `false` | ✅ |
| `enable_local_tcp_fast_redirect` | 本机 TCP 快速重定向 | `false` | ⚠️ 无消费点 |
| `auto_config_kernel_parameter` | 自动写内核参数（ip_forward/forwarding/send_redirects/accept_ra；被改回即纠正） | `false` | ✅ |
| `auto_config_firewall_rule` | 自动配防火墙规则 | `false` | ⚠️ 无消费点 |
| `sniffing_timeout` | 嗅探等待上限 | `100ms` | ✅ |
| `auto_sniff_punt` | 嗅探命中后按规则重选出口（等价 CLI `--sniff-punt`） | `false` | ✅ |
| `tls_implementation` | TLS 实现选择（暂不生效：仅自实现 uTLS 形态，见 ADR-0069） | — | ⚠️ 无消费点 |
| `utls_imitate` | uTLS 指纹族（暂不生效：固定 Chrome-120，见 ADR-0069） | — | ⚠️ 无消费点 |
| `tls_fragment` | TLS 分片开关（暂不生效：见 ADR-0069） | — | ⚠️ 无消费点 |
| `tls_fragment_length` | TLS 分片长度 | — | ⚠️ 无消费点 |
| `tls_fragment_interval` | TLS 分片间隔 | — | ⚠️ 无消费点 |
| `pprof_port` | pprof HTTP 端口（暂不生效：Rust 侧无 Go pprof 等价，见 ADR-0069） | `0` | ⚠️ 无消费点 |
| `mptcp` | MPTCP 开关（拨号 socket 用 IPPROTO_MPTCP；不支持的内核回落 TCP） | `false` | ✅ |
| `bootstrap_resolver` | 启动期解析器（bootstrap） | — | ✅ |
| `fallback_resolver` | 节点域名兜底 DNS（bootstrap 之后、系统解析器之前） | — | ✅ |
| `bandwidth_max_tx` | 发送带宽上限（代理服务端能力） | — | ⚠️ 无消费点 |
| `bandwidth_max_rx` | 接收带宽上限（代理服务端能力） | — | ⚠️ 无消费点 |
| `udphop_interval` | hysteria2 端口跳跃间隔（全局默认；节点 `udphop-interval=` 优先） | `30s` | ✅ |
| `bpf_conn_state_map_size` | conn_state_map 容量（启动时生效） | `262144` | ✅ |
| `relay_idle_timeout` | relay 空闲回收秒数 | `300` | ✅ |
| `udp_idle_timeout` | UDP NAT 会话空闲秒数（普通 NAT 类端点 TTL） | `60` | ✅ |
| `dial_timeout` | 拨号超时秒数 | `5` | ✅ |
| `max_conns` | relay 并发上限（0=不限） | `0` | ✅ |
| `subscription_failover` | 订阅按声明顺序回退（pacman 风格） | `true` | ✅ |
| `subscription_update_interval` | 订阅读周期刷新秒数（0=关） | `21600` | ✅ |
| `watch_config` | 配置热驱动（inotify 事件 + 兜底扫描秒数；0=关） | `0` | ✅ |
| `sub_cache_ttl` | 订阅节点缓存 TTL 秒数 | `1800` | ✅ |
| `sub_fail_ttl` | 失败源负缓存秒数（0=关） | `600` | ✅ |
| `log_file` | 日志文件路径（SIGHUP reopen） | `stdout` | ✅ |
| `status_socket` | 状态面 Unix socket 路径 | `/tmp/sodama-status.sock` | ✅ |
| `geodata_dir` | geoip.dat/geosite.dat 搜索目录（逗号分隔） | — | ✅ |
| `rule_set_update_interval` | rule_set 刷新间隔秒数（0=每次 reload 刷新） | `0` | ✅ |
| `rule_set_cache_dir` | rule_set 磁盘缓存目录 | `$XDG_CACHE_HOME/sodama/rule-set` | ✅ |
| `probe_idle_cap` | 健康探测空闲退避上限秒数（0=不退避） | `600` | ✅ |
| `disable_timestamp` | 日志时间戳开关（P38 扩展键，dae 无） | `false` | ✅ |

## dns

| 键 | 说明 | 默认 | 生效 |
|---|---|---|---|
| `ipversion_prefer` | IPv4/IPv6 偏好（4/6；缺 50ms 偏好等待） | `0` | ✅ |
| `fixed_domain_ttl` | 固定域名 TTL 表（`域名: 秒数` 子段） | — | ✅ |
| `upstream` | DNS 上游 tag → URL 映射（udp/tcp/tcp+udp/tls/https） | `8.8.8.8:53` | ✅ |
| `routing` | DNS 请求/应答路由（geosite/reject/asis/tag 等） | — | ✅ |
| `bind` | 明文 DNS 监听（`ip:port` = 仅 UDP；`udp+tcp://ip:port`；供 AdGuard/mosdns 指上游；缺省 = 不开监听） | `缺省不开` | ✅ |
| `optimistic_cache` | 乐观缓存（RFC 8767 stale）开关 | `true` | ✅ |
| `optimistic_cache_ttl` | 乐观缓存 TTL 秒数 | `60` | ✅ |
| `optimistic_stale_reply_ttl` | 过期应答可回窗口秒数 | `30` | ✅ |
| `max_cache_size` | DNS 缓存容量 | `4096` | ✅ |

## group

| 键 | 说明 | 默认 | 生效 |
|---|---|---|---|
| `filter` | 成员过滤表达式（可多行，OR 组合） | — | ✅ |
| `policy` | 选节点策略（min/min_moving_avg/min_avg10/random/fixed(n)） | `min` | ✅ |
| `tcp_check_url` | 组级健康检查目标（覆盖 global） | — | ✅ |
| `tcp_check_http_method` | 组级探测 HTTP 方法（覆盖 global；不校验） | — | ✅ |
| `udp_check_dns` | 组级 UDP 检查目标（覆盖 global） | — | ✅ |
| `check_interval` | 组级探测周期（0=继承 global；不得为负） | `继承` | ✅ |
| `check_tolerance` | 组级失败容忍（覆盖 global） | `继承` | ✅ |

## 其它段

`include` / `routing` / `subscription` / `node` / `rule_set` / `dns.fixed_domain_ttl` 见 `docs/deploy.md`、`sodama/lab/gateway.dae` 示例与 `docs/capability-gap-review.md`。
