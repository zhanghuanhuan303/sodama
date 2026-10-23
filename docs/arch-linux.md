# sodama on Arch Linux

本文是 **Arch Linux** 上的安装与使用说明（AUR 包、systemd、配置文件、Web 面板）。
通用部署模型（数据面前置、`install.sh`、lab 拓扑）见 [`deploy.md`](deploy.md)；
OpenWrt/软路由见 [`openwrt.md`](openwrt.md)。

> **包结构**（`sodama` / `sodama-bin` 相同）：
>
> | 路径 | 内容 |
> |---|---|
> | `/usr/bin/sodama` | 引擎（用户态控制面 + relay/DNS） |
> | `/usr/lib/sodama/sodama-ebpf` | eBPF 数据面对象（TC/TCX、cgroup、sk_skb、fentry、XDP） |
> | `/usr/lib/sodama/datapath` | 数据面对脚本（netns/veth/静态邻居/策略路由/sysctl） |
> | `/usr/bin/sodama-panel` + `/usr/share/sodama-panel/dist` | Web 面板（后端 + wasm 前端） |
> | `/usr/lib/systemd/system/sodama{,-panel}.service` | systemd 单元 |
> | `/etc/sodama/config.dae` | 主配置（`backup`：升级保留改动） |
> | `/etc/sodama/sodama.conf` | 数据面对环境（`EnvironmentFile`） |
> | `/etc/sodama-panel/panel.conf` | 面板配置（`backup`） |
> | `/usr/share/doc/sodama/` | 本文 + `config-reference.md` |

---

## 1. 内核要求

| 项 | 要求 | Arch 官方内核 |
|---|---|---|
| 版本 | ≥ 5.17（eBPF 有界循环）；≥ 6.6 走 TCX 挂载（否则回退 cls_bpf） | ✓（`uname -r` 应 ≥ 6.6） |
| BTF | 必需（BTF map / verifier） | ✓ `ls /sys/kernel/btf/vmlinux` |
| BPF/TC/cgroup/netns/veth | `CONFIG_BPF_SYSCALL` `CONFIG_NET_CLS_BPF` `CONFIG_NET_SCH_INGRESS` `CONFIG_CGROUP_BPF` `CONFIG_NET_NS` `CONFIG_VETH` | ✓ 默认开启 |
| bpffs（可选） | `bpftool` 排查用；引擎不依赖（钩子随进程退出摘除） | `mount -t bpf bpf /sys/fs/bpf`（可写进 `/etc/fstab`） |

快速自检：

```bash
uname -r
ls /sys/kernel/btf/vmlinux            # 必须存在
zcat /proc/config.gz 2>/dev/null | grep -E 'CONFIG_(BPF_SYSCALL|NET_CLS_BPF|NET_SCH_INGRESS|CGROUP_BPF|DEBUG_INFO_BTF|NET_NS|VETH)=y' \
  || grep -E 'CONFIG_(BPF_SYSCALL|NET_CLS_BPF|NET_SCH_INGRESS|CGROUP_BPF|DEBUG_INFO_BTF|NET_NS|VETH)=y' /boot/config-linux 2>/dev/null
```

**不要**在容器里部署（需要 `CAP_BPF`/`CAP_NET_ADMIN`/netns）。

---

## 2. 安装（AUR）

```bash
# 推荐：预编译包（musl 静态，含面板；无构建依赖）
yay -S sodama-bin            # 或 paru -S sodama-bin

# 源码包（从 git tag 构建；需要预装 nightly + rust-src + wasm32 target）
rustup toolchain install nightly --component rust-src
rustup target add wasm32-unknown-unknown
yay -S sodama
```

本地打包（未发布到 AUR 时）：

```bash
git clone https://github.com/zhanghuanhuan303/dae-rust.git
cd dae-rust/packaging/aur/sodama-bin
makepkg -si
# 或源码包：cd ../sodama && makepkg -si
```

> 源码包与 `sodama-bin` 冲突（`conflicts`/`provides`），不要同时安装。

---

## 3. 配置（`/etc/sodama/config.dae`）

```bash
sudo $EDITOR /etc/sodama/config.dae
```

最少要改三处：

1. **接口名**（`ip -br link`；默认路由接口 `ip route show default`）：
   ```
   global {
       wan_interface: wan0     # 例如 enp1s0 / eth0
       lan_interface: br0      # 例如 br-lan / enp2s0；单机代理写 none
   }
   ```
2. **节点或订阅**（二选一）：
   ```
   node { my: 'vless://uuid@host:443?security=tls&sni=example.com#node1' }
   # 或
   subscription { tag: main  url: 'https://example.com/sub' }
   ```
3. **权限**：文件必须 `0640`（同组不可写、其他用户不可读）：
   ```bash
   sudo chmod 640 /etc/sodama/config.dae
   ```

校验与生效：

```bash
sudo sodama validate /etc/sodama/config.dae   # 只读检查（不加载 eBPF、不联网）
sudo systemctl reload sodama                  # SIGHUP 热重载（规则/订阅/配置）
```

配置项全集：`sodama config-doc --format md`（或 `/usr/share/doc/sodama/config-reference.md`）。
常用 global：`log_level`、`tproxy_port`、`check_interval`、`tcp_check_url`、
`auto_config_kernel_parameter`（自动写转发相关 sysctl 并在被改回时纠正）。

---

## 4. systemd（标准用法）

```bash
sudo systemctl enable --now sodama        # 开机自启 + 立即启动
systemctl status sodama                   # 状态（Type=notify：启动完成才 READY）
journalctl -u sodama -f                   # 跟随日志（同时写 /var/log/sodama.log）
sudo systemctl reload sodama              # 热重载（不断流）
sudo systemctl restart sodama             # 重建数据面（brief 断流）
sudo systemctl stop sodama                # 停止并清理 netns/veth（ExecStopPost）
```

单元要点：

- `Type=notify`：进程 `sd_notify(READY)` 后才算启动完成（含订阅拉取/规则下发）；
- `ExecStartPre=/usr/lib/sodama/datapath setup` → 建 netns/veth/策略路由/sysctl；
  `ExecStopPost=... teardown` → 清理；
- `ExecReload` 发 `SIGHUP`（等价 `sodama reload`）；
- 配置被拒（`validate`/加载失败）走 `Restart=on-abnormal`，不会无限重启；
- `CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN` + `LimitNOFILE=1048576`。

**覆盖参数**（节点/订阅也可以放命令行，而不是 config）：

```bash
sudo systemctl edit sodama
# [Service]
# ExecStart=
# ExecStart=/usr/bin/sodama --config /etc/sodama/config.dae \
#     --ebpf /usr/lib/sodama/sodama-ebpf \
#     --status-socket /run/sodama/status.sock \
#     --log-file /var/log/sodama.log \
#     --dialer 'vless://uuid@host:443?security=tls#node1'
```

> systemd 里 URL 的 `%` 必须写 `%%`；把订阅 URL 放进文件（`--subscribe file:///etc/sodama/sub.url`，`chmod 600`）可避免。

---

## 5. 数据面对（`datapath`）

sodama 的 loader **不自建**拓扑；透明代理回程需要：

- netns `daens` + veth `dae0`/`dae0peer`；
- `169.254.0.11/32` + 静态邻居（让 redirect 的 L3 头可发出）；
- `fwmark 0x8000000` 策略路由（table 2023，本地投递）；
- `ip_forward=1`、`rp_filter=0`、`accept_local=1`。

这些由 `/usr/lib/sodama/datapath` 完成（systemd 自动调用）。行为可在
`/etc/sodama/sodama.conf` 调整：

```ini
SODAMA_DATAPATH=1          # 0 = 跳过（用户自管拓扑 / 只跑本机代理）
#DAE_NS=daens
#DAE0=dae0
#DAE0PEER=dae0peer
#SODAMA_DATAPATH_IPV6=1
```

排查：

```bash
sudo /usr/lib/sodama/datapath status     # netns/veth/策略路由/sysctl
sudo /usr/lib/sodama/datapath setup      # 幂等：已存在直接成功
sudo /usr/lib/sodama/datapath teardown   # 幂等清理
```

**网关模式**（默认）：LAN 设备网关/DNS 指向本机，`lan_interface` 填 LAN 网桥。
**单机模式**：`lan_interface: none`（本机流量经 `wan_egress` 钩子），datapath 仍需要
（回程注入），除非你自己处理了拓扑。

> sodama 用 TC/eBPF + tproxy socket，**不需要** nftables/iptables 的 REDIRECT 规则；
> 防火墙只需保证 LAN 到本机 `tproxy_port` 与 LAN 转发策略符合你的预期。

---

## 6. Web 面板（`sodama-panel`）

```bash
sudo systemctl enable --now sodama-panel
# 浏览器访问 http://<路由器 LAN IP>:8080
systemctl status sodama-panel
journalctl -u sodama-panel -f
```

`/etc/sodama-panel/panel.conf` 常用项：

| 键 | 默认 | 说明 |
|---|---|---|
| `bind` | `0.0.0.0:8080` | 监听地址（仅 LAN；勿暴露公网） |
| `static_dir` | `/usr/share/sodama-panel/dist` | 前端资源（包安装位置） |
| `socket` | `/run/sodama/status.sock` | 引擎状态面（与 `sodama.service` 一致） |
| `token` | 空 | 空 = 免认证（LAN）；设置后需登录（HttpOnly Cookie） |
| `enable_actions` | `0` | 允许面板触发 reload/suspend/resume |
| `log_file` | `/var/log/sodama.log` | 日志页数据源 |
| `tls` | 未设 | `tls = 1` 时启用 HTTPS（首次启动自签，key 0600） |

建议：LAN 内使用；需要远程访问时用 SSH 隧道（`ssh -L 8080:192.0.2.10:8080 root@gateway`）
或反代 + token + HTTPS。

面板能力：总览（RSS/连接/吞吐/节点/数据面卡片）、配置页（订阅/规则集/分流条目/内核参数
在线编辑，先 `validate` 后落盘 + 热重载回执）、日志尾、运维工具（reload/abort/drain、
`trace` 抓取、`sysdump` 诊断包）。

---

## 7. 常用命令

```bash
sodama status --socket /run/sodama/status.sock --json | jq .   # 完整状态
sodama metrics --socket /run/sodama/status.sock                # Prometheus 文本
sodama trace --socket /run/sodama/status.sock --seconds 10     # 判决事件（内核侧过滤）
sudo sodama sysdump --socket /run/sodama/status.sock --out /tmp/sodama-dump.tar.gz
sodama reload --socket /run/sodama/status.sock --drain=5       # 排空旧代会话再重载
sodama --version
```

---

## 8. 升级与卸载

```bash
# AUR 升级
yay -Syu                                  # 或 paru -Syu
# 配置被更新时：检查 .pacnew
sudo pacman -Syu sodama-bin
sudo find /etc -name '*.pacnew' -print    # 手动合并后删除

# 卸载（保留配置）
sudo systemctl disable --now sodama-panel sodama
sudo pacman -R sodama-bin                 # 或 sodama
sudo rm -rf /etc/sodama /etc/sodama-panel /var/log/sodama.log*   # 确认不再需要时
```

`datapath` 的 `ExecStopPost` 会在停止时清理 netns/veth；若进程被 `kill -9`，
手动跑一次 `sudo /usr/lib/sodama/datapath teardown`。

---

## 9. 排障清单

| 症状 | 检查 |
|---|---|
| 启动失败：`加载配置失败` | `sodama validate /etc/sodama/config.dae`；配置文件权限必须 ≤0640 |
| `netns daens 不存在` / 挂载失败 | `systemctl status sodama` 看 `ExecStartPre`；`sudo /usr/lib/sodama/datapath setup` |
| `加载 eBPF 失败`（权限/verifier） | 内核 ≥5.17、`ls /sys/kernel/btf/vmlinux`、`journalctl -u sodama -b` |
| 节点全部不可用 | `sodama status ... --json \| jq '.group'`；订阅 URL/本地时间/网络 |
| DNS 不生效 | 确认 LAN 设备 DNS 指向本机；`dns.upstream` 配置；`status.dns` |
| 面板打不开 | `ss -ltnp \| grep 8080`；`panel.conf` 的 `bind`；防火墙 |
| 面板日志页空白 | `log_file` 路径与 `sodama.service` 的 `--log-file` 一致 |
| 版本带 `-dirty` | 源码构建时工作树有已跟踪改动（未跟踪文件不再计入，自 v1.0.0） |

更多：`journalctl -u sodama -b`、`/var/log/sodama.log`、`docs/deploy.md` §0（部署模型）。

---

## 10. AUR 维护（发布新版本）

```bash
# 1) 更新版本
#    sodama/loader/Cargo.toml（+ ebpf-rs/ebpf-logic）、panel/Cargo.toml、install/openwrt/Makefile
# 2) 生成发布 tarball（x86_64 musl 静态 + 面板）
packaging/make-release.sh
# 3) 上传 tarball 到 GitHub Release（tag v<ver>），把 sha256 回填到
#    packaging/aur/sodama-bin/PKGBUILD
# 4) 刷新 .SRCINFO 并本地验证
cd packaging/aur/sodama-bin && makepkg --printsrcinfo > .SRCINFO && makepkg -si
cd ../sodama && makepkg --printsrcinfo > .SRCINFO
# 5) 推送到 AUR（两包分别）
```
