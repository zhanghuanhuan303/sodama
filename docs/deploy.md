# sodama 部署（systemd / 真机网关）

本文档描述把 sodama 作为真机透明代理网关部署的两种方式：**lab 一键脚本**
（`sodama/lab/gateway.sh`，当前完整可用）与 **systemd 单元 + `install/install.sh`**
（工程化路径，单元是骨架，需要补齐数据面前置与节点参数）。所有行为以仓库代码与脚本
为准，参数清单在 `sodama/loader/src/main.rs` 的 `usage()`。

> 约定：下文命令若从仓库根目录执行，路径写作 `sodama/...`；从 `sodama/` 目录执行时
> 去掉该前缀。

---

## 0. 部署模型（先读，避免踩坑）

> OpenWrt / 路由器（musl + ipk + procd）见 [`openwrt.md`](openwrt.md)：含 musl 交叉构建、
> 内核 fragment（**官方镜像默认未开 NAMESPACES/NET_NS，需自编内核**）与 QEMU 冒烟。

sodama 的 loader **只做三件事**：加载 eBPF 对象、挂 tc 钩子、跑 relay/DNS 控制面。
它**不会自建** netns、veth、路由与 sysctl：

- 启动时按 `--daens <名>` 打开 `/var/run/netns/<名>`（默认 `daens`），不存在就直接报错退出；
- 按 `--dae0`/`--dae0peer` 找 veth 两端（默认 `dae0`/`dae0peer`），按 `--lan`/`--wan`
  找要挂钩子的网卡（默认 `landae`/`wan`，`--lan none` = 本机网关模式不挂 LAN 钩子）。

这些前置目前由 `sodama/lab/gateway.sh up` 负责建立（真机网关的完整实现，见
`docs/adr/ADR-0029`），`down` 负责回滚。因此：

| 方式 | 适用 | 生命周期 | 数据面前置 |
|---|---|---|---|
| A. `lab/gateway.sh up/down` | 真机验收、日常使用 | 脚本管进程 + 拓扑 | 脚本自动建立/清理 |
| B. `install/install.sh` + systemd | 需要开机自启/进程托管 | systemd 管进程，拓扑需自备 | **需外部预先建立**（见 §4） |

`install/sodama.service` 里的 `ExecStart` 是任务规定的最小骨架，直接 `systemctl start`
在缺少前置/节点参数时**会失败**（`Restart=on-failure` 会不断重试）。按 §5 用 drop-in
补齐后再启动。

---

## 1. 前置条件

| 项 | 要求 / 现状 | 检查 |
|---|---|---|
| 内核 | ≥ 5.17（eBPF 有界循环）；≥ 6.6 走 TCX 挂载路径（见 `sodama/README.md`「依赖」） | `uname -r` |
| 内核 BTF | BTF map 依赖内核 BTF，主流发行版自带 | `ls /sys/kernel/btf/vmlinux` |
| cgroup2 | pname（按进程名分流）需要；找不到只告警不致命，pname 规则不命中 | `mount \| grep cgroup2` |
| bpffs | loader 不写 `/sys/fs/bpf`（钩子由进程持有的 link fd 管理，进程退出即摘除）；挂上 `bpffs` 便于 `bpftool` 排查即可 | `mount \| grep '/sys/fs/bpf'` |
| 权限 | root，或 systemd 单元的 `CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN`（见 §5） | `id -u` |
| 工具面 | `ip`（建拓扑/排查）、`bpftool`（可选排查）、`journalctl` | `command -v ip bpftool` |
| 构建链 | stable + nightly（含 `rust-src`）+ `bpf-linker`；见 §2 | `rustup toolchain list` |

容器/CI 里通常没有 `CAP_SYS_ADMIN`、不能建 netns/挂 tc，**不要在容器里部署**；
CI（`.github/workflows/ci.yml`）只做「eBPF 编译 + loader 编译/单测」，不附加 eBPF。

## 2. 构建

```bash
cd sodama
lab/lab.sh build              # = cargo build --release + lab/build-ebpf-rs.sh
# 或分开：
lab/build-ebpf-rs.sh          # nightly + rust-src + bpf-linker → ebpf-rs/target/bpfel-unknown-none/release/sodama-ebpf
cargo build --release         # → target/release/sodama
```

已知可用工具链组合（`sodama/NOTES.md` §11.13、`docs/adr/ADR-0023`）：

- `rustc 1.101.0-nightly (5c543b0b8 2026-09-29)` + `rust-src`（`-Z build-std=core` 需要）；
- `bpf-linker 0.11.1`（默认 feature 即 LLVM 23；bpf-linker 与 nightly 的 LLVM 版本必须匹配）。

`lab/build-ebpf-rs.sh` 会检查 nightly 与 `bpf-linker` 并给出安装提示；对象构建配置在
`sodama/ebpf-rs/.cargo/config.toml`（目标 `bpfel-unknown-none`、`link-arg=--btf`）。

## 3. systemd 安装（install.sh）

```bash
install/install.sh --help
sudo install/install.sh            # 默认：已有产物直接装；缺产物则构建
sudo install/install.sh --build    # 强制重建后再装
sudo install/install.sh --no-build # 只装已构建产物
install/install.sh --dry-run       # 只打印命令，不写入（可非 root）
sudo install/install.sh --uninstall
```

安装布局：

| 路径 | 内容 |
|---|---|
| `/usr/local/bin/sodama` | loader |
| `/usr/lib/sodama/sodama-ebpf` | eBPF 数据面对象（对应 `--ebpf`） |
| `/etc/systemd/system/sodama.service` | systemd 单元 |
| `/etc/sodama/config.dae` | 样例配置（仅当不存在时从 `sodama/lab/gateway.dae` 拷贝，权限 640） |
| `/etc/sodama/blocklist.txt` | 同上（`qname(file: 'blocklist.txt')` 相对配置文件目录解析） |

`--uninstall` 会 `systemctl disable --now`、删除上述二进制与单元，**保留** `/etc/sodama`
（需要彻底清理时手动 `sudo rm -rf /etc/sodama`）。

## 4. 数据面前置（systemd 方式必须自备）

若走 systemd（方式 B），需要先建立与 drop-in 参数一致的拓扑。等价命令摘自
`lab/gateway.sh up`（命名与 gateway.sh 对齐）：

```bash
# 以「本机网关」为例：只挂宿主 WAN 网卡钩子，不开 LAN。
IFACE=wlan0            # 换成你的默认路由网卡
ip netns add gwdae
ip link add dae0gw type veth peer name dae0gwpeer
ip link set dae0gwpeer netns gwdae
ip link set dae0gw up
ip -n gwdae link set lo up
ip -n gwdae link set dae0gwpeer up
ip -n gwdae addr add 169.254.0.11/32 dev dae0gwpeer
ip -n gwdae route add 169.254.0.1/32 dev dae0gwpeer scope link
ip -n gwdae route add default via 169.254.0.1 dev dae0gwpeer
MAC="$(ip link show dev dae0gw | awk '/link\/ether/ {print $2; exit}')"
ip -n gwdae neigh add 169.254.0.1 lladdr "$MAC" dev dae0gwpeer nud permanent
ip netns exec gwdae sysctl -qw net.ipv4.conf.dae0gwpeer.accept_local=1
ip netns exec gwdae sysctl -qw net.ipv4.ip_nonlocal_bind=1
ip -n gwdae rule add fwmark 0x8000000/0x8000000 table 2023
ip -n gwdae route add local default dev lo table 2023
sysctl -qw net.ipv4.conf.all.rp_filter=0
sysctl -qw net.ipv4.conf.default.rp_filter=0
sysctl -qw net.ipv4.conf.dae0gw.accept_local=1
```

IPv6 数据面（`fe80::ecee:eeff:feee:eeee`、策略路由等）见 `lab/gateway.sh` 中
`NO_IPV6=0` 的分支；想要只跑 v4 用 gateway.sh 的 `--no-ipv6`（loader 侧 IPv6 不可用时
会自动降级为仅 v4，无对应 CLI 开关）。

清理（停 unit 后再执行）：

```bash
ip netns del gwdae; ip link del dae0gw
# 以及恢复 rp_filter / accept_local 等 sysctl（gateway.sh down 也会做）
```

> ⚠️ 不要用 `lab/gateway.sh down` 去清理 systemd 实例：它会 `pkill -f "daens gwdae"`
> 并 `ip netns del`，可能误杀 systemd 托管的 loader、触发 `Restart=on-failure` 重启竞争。
> 正确顺序：先 `sudo systemctl stop sodama`，再清理/回滚。

## 5. systemd 单元与 drop-in

`/etc/systemd/system/sodama.service` 的核心配置（完整文件见 `install/sodama.service`）：

```ini
[Service]
Type=simple
ExecStart=/usr/local/bin/sodama --config /etc/sodama/config.dae --ebpf /usr/lib/sodama/sodama-ebpf
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN
LimitNOFILE=1048576
```

补齐实际参数（节点/订阅 + 数据面命名 + 可选状态面）用 drop-in：

```bash
sudo systemctl edit sodama
```

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/sodama --config /etc/sodama/config.dae \
    --ebpf /usr/lib/sodama/sodama-ebpf \
    --lan none --wan wlan0 \
    --daens gwdae --dae0 dae0gw --dae0peer dae0gwpeer \
    --dialer 'anytls://<节点URL>'
# 订阅：把 URL 放进 /etc/sodama/sub.url（chmod 600），改用：
#   --subscribe file:///etc/sodama/sub.url --group proxy
# 可选状态面（配合 RuntimeDirectory=sodama，见下）：
#   --status-socket /run/sodama/status.sock
RuntimeDirectory=sodama
RuntimeDirectoryMode=0750
```

- systemd 单元里 URL 的 `%` 必须写成 `%%`；放进订阅文件可绕开。
- `--lan none` = 不挂 LAN 钩子（纯本机网关），与 `gateway.sh` 用法一致；
  `--dialer`/`--subscribe`、`--dial-mode`、`--group`、`--geodata-dir`、`--dns-upstream`
  等参数与 `usage()` 完全一致，不要在单元里写仓库文档没出现的参数。
- 样例 `config.dae` 来自 `lab/gateway.dae`：它的 `dns.routing` 引用了
  `geosite:category-ads-all` / `geosite:cn`，需要 geosite 数据；把 `geosite.dat`/`geoip.dat`
  放进 `/etc/sodama/`（配置所在目录会被自动搜索），或用 `--geodata-dir`/环境变量
  `DAE_LOCATION_ASSET` 指定，否则启动会在编译 `dns.routing` 时失败。
- 首次启动前建议先用免 root 子命令做静态检查：
  `sodama validate /etc/sodama/config.dae`、
  `sodama extract-routing /etc/sodama/config.dae`。

## 6. 日常操作

```bash
sudo systemctl enable --now sodama   # 开机自启 + 启动
systemctl status sodama
sudo systemctl reload sodama         # SIGHUP：重读 --config/--rules 热重载（+ reopen 日志文件）
sudo systemctl stop sodama           # 退出即摘钩子，流量恢复直连
sudo systemctl restart sodama        # 改 drop-in 后重启
```

回滚到 lab 工作流：

```bash
sudo systemctl disable --now sodama
cd sodama && sudo lab/gateway.sh up     # 脚本自建拓扑并启动同名模式
```

## 7. 日志

- 默认输出到 stdout/stderr，systemd 下进 journal：
  `journalctl -u sodama -f`、`journalctl -u sodama --since '10 min ago'`。
- 想落文件：在 drop-in 里加 `--log-file /var/log/sodama.log`；`SIGHUP`
  （`systemctl reload`）会 reopen 日志文件，可直接配 logrotate。
- 真机脚本方式日志在 `/tmp/sodama-gw.log`（gateway.sh）、`/tmp/sodama.log`（lab.sh），
  以及 `--log-file` 指定的路径。

## 8. 状态面 / 运维 CLI

loader 只在显式传 `--status-socket <path>` 时创建 Unix socket；客户端子命令默认连
`/tmp/sodama-status.sock`（`sodama/loader/src/main.rs` 的 `parse_socket_args`），
需要 socket 权限（通常 root）：

```bash
sudo sodama status   [--socket /run/sodama/status.sock] [--json]
sudo sodama reload   [--socket ...]     # 等价 kill -HUP，同步等结果
sudo sodama suspend  [--socket ...]     # no-load 挂起（fail-open），resume 恢复
sudo sodama resume   [--socket ...]
sudo sodama metrics  [--socket ...]     # Prometheus 文本
sudo sodama sysdump  [--socket ...] [--out <file>]
sodama validate <config.dae>            # 无需 root / socket
```

未配置 `--status-socket` 时无法用 `status`/`metrics`/`reload` 等子命令（服务端没建 socket）：
重载走 `systemctl reload`（SIGHUP），状态看 `journalctl`；需要子命令就在 drop-in 里加
`--status-socket`（建议 `/run/sodama/status.sock` + `RuntimeDirectory=sodama`）。

配置热驱动（P35）：inotify 事件驱动为默认（毫秒级 + 100ms 去抖；事件名过滤 + 快照复核），
`global { watch_config: 10 }` 或 `--watch-config 10` 启用（值 = 无 inotify 时的兜底扫描秒数）；
自动 reload 走订阅节点缓存（`sub_cache_ttl`，默认 1800s；失败源负缓存 `sub_fail_ttl` 默认
600s——未变源不打订阅服务器；手动 `reload`/`systemctl reload` 仍强制重拉）。
行为参数可全部写进 `global`（`dial_mode/dial_timeout/sniffing_timeout/watch_config/sub_cache_ttl/
sub_fail_ttl/geodata_dir/log_file/status_socket` 等）——**配置文件即唯一事实来源**，CLI 仅作调试覆盖。

多订阅与默认配置目录（P34/P35）：config `subscription` 段按**声明顺序回退**（pacman 镜像风格）——
首个有 alive 节点的源生效，全部标死才切下一源；`global { subscription_failover: false }`
关闭回退（旧池化语义），状态面 `group.active_tag` 可查当前活动源。loader 未给
`--config/--rules` 时按以下顺序自动选择：`$XDG_CONFIG_HOME/sodama/config.dae` →
`~/.config/sodama/config.dae` → `/etc/sodama/config.dae`（无 home / 无 XDG 的软路由/OpenWrt
落到系统目录；`/etc` 候选需可读，非 root 读到 640 root:root 时视为不存在）；config 内相对
订阅路径按配置目录解析，单行 http(s) URL 文件（如 `subN.url`）自动按 URL 抓取。systemd 场景
建议 drop-in 显式 `--config /etc/sodama/config.dae`（更直观，且 `HOME` 常为 `/`）。

规则集与用户名单（P36）：`rule_set { tag: 'url|路径' }` 支持标准格式（Clash rule-provider
YAML / sing-box rule-set JSON / 纯文本域名列表），远程 URL 自动下载并按
`global.rule_set_update_interval`（缺省 86400s；0=每次 reload）刷新，缓存目录缺省走
XDG cache → `~/.cache` → `/var/cache`（可用 `global.rule_set_cache_dir` 指定；OpenWrt 等
无 home 环境自动落到 `/var/cache/sodama/rulesets`）；路由用 `domain(ruleset: tag)` 引用。
用户名单文件（`rules/user_proxy.txt` / `rules/user_direct.txt`，相对配置目录解析）已纳入
inotify 监听——**编辑名单即热生效**，无需改 config 或重启。

## 9. 升级 / 回滚

升级：

```bash
cd sodama && git pull
lab/lab.sh build                # 或 install/install.sh --build
sudo install/install.sh         # 覆盖安装 + daemon-reload
sudo systemctl restart sodama
```

回滚：

- 二进制无内置版本管理：安装前自行备份 `cp /usr/local/bin/sodama{,.bak}`，
  回滚即用旧二进制覆盖并 `systemctl restart`；
- 完全回退到脚本工作流：`sudo systemctl disable --now sodama` 后
  `sudo lab/gateway.sh down`（幂等，杀进程、删 netns/veth、恢复 sysctl）；
- loader 进程退出（正常或异常）时 tc/TCX 钩子随 link fd 自动摘除，网络立即恢复直连
  （P13 实测结论，见 `sodama/README.md`）。

## 10. 与 lab/gateway.sh 的关系

| 能力 | `lab/gateway.sh` | systemd（本目录） |
|---|---|---|
| 建/拆 netns、veth、路由、sysctl | ✅ `up`/`down` | ❌ 需自备（§4） |
| 启动/停止 loader | ✅ nohup + pid 文件 | ✅ systemd |
| 接口探测（默认路由网卡）、DNS 探测 | ✅ | ❌ 显式写参数 |
| 节点/订阅参数 | ✅ `--node/--subscribe/--group` | drop-in 里 `--dialer/--subscribe` |
| 热重载 | `kill -HUP` | `systemctl reload` |
| 日志轮转 | `--log-file` + SIGHUP | journal（或同左） |
| 状态面 | `--status-socket /tmp/sodama-gw.sock` | 可选，建议放 `/run/sodama/` |

结论：**当前生产可用入口是 `lab/gateway.sh`**；systemd 适合把进程托管、开机自启纳入
现有运维体系的环境，数据面拓扑需由你已有的网络管理方式（或 §4 命令）提供。

## 11. 故障排查

| 现象 | 原因 / 处理 |
|---|---|
| `open /var/run/netns/<名>: No such file` | netns 未建：跑 §4 或改用 `lab/gateway.sh up` |
| `if_nametoindex ...` / attach 失败 | `--wan/--lan` 写错或网卡不存在；本机网关用 `--lan none --wan <默认路由网卡>` |
| 启动即退出：`编译 dns.routing` 报缺 geodata | 样例配置需要 geosite.dat/geoip.dat；放 `/etc/sodama/` 或 `--geodata-dir` |
| 启用了样例但仍直连/代理不通 | 没有 dialer：drop-in 补 `--dialer` 或 `--subscribe`；`journalctl` 里搜 `relay dialer` |
| pname 规则不命中 | 无 cgroup2 挂载；日志有 `pname: ...` 告警（不致命） |
| systemd 反复重启 | `Restart=on-failure` 生效：先 `systemctl status`/`journalctl -u` 看首个错误，修复后再 start；急停用 `systemctl stop` |
| 修改配置不生效 | 确认走了 `systemctl reload`（SIGHUP）；`--config` 路径与权限（loader 要求配置文件 640，`gateway.sh` 会 chmod） |
| 与 gateway.sh 混用后网络异常 | 先 `systemctl stop sodama`，再 `lab/gateway.sh down`（顺序见 §4 警告） |
