# sodama 在 OpenWrt 上的使用说明（v1.0.0）

> 目标读者：要把 **sodama**（Rust 写的 eBPF 透明代理网关，dae 的重写）装到 OpenWrt 软路由上的人。
> 本文是**可独立阅读**的完整说明：平台前提 → 安装 → 配置 → 拓扑 → 验证 → 排障 → 升级卸载。
> 技术细节与历史验证记录见 [`openwrt.md`](openwrt.md)；通用配置项见 [`config-reference.md`](config-reference.md)。

---

## 0. 一句话结论（先读这段，避免白折腾）

| 项 | 要求 | 说明 |
|---|---|---|
| 内核 | **Linux ≥ 6.6** | 6.6+ 用 TCX（`bpf_link`）挂载；<6.6 不支持 |
| 系统 | **OpenWrt ≥ 24.10** | 23.05（5.15 内核）不行 |
| 内核开关 | **`CONFIG_NAMESPACES` + `CONFIG_NET_NS` 必须开** | ⚠️ **官方镜像默认没开**（`# CONFIG_NAMESPACES is not set`），必须**自编一次内核/镜像**（附录 A 有现成片段） |
| 架构 | x86_64 / aarch64 / armv7 | 单文件 musl 静态二进制，无动态依赖 |
| 体积 | 二进制 ~8 MB + eBPF 对象 ~1 MB | 稳态内存 ~12 MB |
| 额外包 | `ip-full`（不能用 busybox 的 ip）、`kmod-veth` | ipk 已声明依赖 |
| BTF | 非必需 | 当前 eBPF 程序不用 CO-RE；开了便于调试 |

**为什么必须自编内核**：sodama 需要一个固定 netns（`daens`）承载 tproxy 监听，OpenWrt 官方镜像把
namespace 全关了。dae（Go 版）同样依赖 netns，这不是 sodama 新增的约束。自编一次约 30–60 分钟，之后
升级 OpenWrt 才需要重编。

---

## 1. 安装

### 1.1 用 ipk（推荐）

包名 `sodama`，内容：静态二进制、eBPF 对象、数据面对脚本、procd 初始化、uci 配置、配置模板与规则集。

```sh
# 设备上
opkg install /tmp/sodama_1.0.0-2_<arch>.ipk
```

如果手上没有现成 ipk，按下面两步自己出一个（需要 OpenWrt SDK）：

```sh
# ① 开发机：交叉编译（需要 rustup target + zig + cargo-zigbuild）
sodama/lab/build-openwrt.sh --arch aarch64 --sdk-payload install/openwrt
#   产物：install/openwrt/prebuilt/{sodama,sodama-ebpf}

# ② SDK 内：出 ipk
cp -r install/openwrt <sdk>/package/sodama
cd <sdk> && make package/sodama/compile V=s
#   → bin/packages/<arch>/base/sodama_1.0.0-2_<arch>.ipk
```

> `--arch` 支持 `x86_64` / `aarch64` / `armv7`。`--sdk-payload` 只能配单个架构（避免产物混淆）。

### 1.2 手动部署（不用 ipk）

把两个文件拷过去即可，其余是可选资产：

| 目标路径 | 来源 | 必需 |
|---|---|---|
| `/usr/bin/sodama` | `build/openwrt/<arch>/sodama`（`chmod 755`） | ✅ |
| `/usr/lib/sodama/sodama-ebpf` | `build/openwrt/<arch>/sodama-ebpf`（`chmod 644`） | ✅ |
| `/usr/lib/sodama/sodama-datapath` | `install/openwrt/files/sodama-datapath`（`chmod 755`） | ✅ |
| `/etc/sodama/config.dae` | 见 §2（`chmod 640`） | ✅ |
| `/etc/sodama/rules/*.txt`、`/etc/sodama/blocklist.txt` | `install/openwrt/files/` | 建议 |
| `/etc/init.d/sodama`、`/etc/config/sodama` | `install/openwrt/files/` | 用 procd 时需要 |

### 1.3 装完先自检（不启动服务）

```sh
sodama --version                     # 应输出 1.0.0-gxxxx 与平台
ip netns add probe && ip netns del probe   # 有输出=不支持；没输出=OK（验证内核 NAMESPACES）
sodama validate /etc/sodama/config.dae     # 语法/权限/规则编译数
```

`validate` 会打印 `routing: N 条可编译`。**N=0 时引擎会拒绝启动**（见排障）。

---

## 2. 配置（`/etc/sodama/config.dae`）

### 2.1 最小可用配置

```sh
vi /etc/sodama/config.dae
```

必须改的只有两处：

1. **接口**：⚠️ **OpenWrt 上以 uci 为准**（procd 会显式传 `--wan/--lan/--dual`，命令行优先于
   本文件里的 `*_interface` 键，见 §3）。`config.dae` 里这一项只作说明，保持默认即可：
   ```
   global {
       wan_interface: wan
       lan_interface: none
   }
   ```
2. **出口**（二选一）：
   ```
   node { my: 'vless://uuid@host:443?security=tls&sni=example.com#node1' }
   # 或（键 = 标签，值 = 订阅 URL；可写多个，按声明顺序回退）
   subscription { main: 'https://example.com/sub' }
   ```

保存后：

```sh
chmod 640 /etc/sodama/config.dae     # 权限硬要求：同组不可写、其他用户不可读
sodama validate /etc/sodama/config.dae
```

### 2.2 包内提供两套模板

| 模板 | 位置 | 适用 | 依赖 |
|---|---|---|---|
| min（默认） | `/etc/sodama/config.dae` | 单机 / 轻量网关：国内常用域名（含国产 AI API）直连，其余走代理 | 无 |
| gateway | `/etc/sodama/config-gateway.dae` | 完整网关：`geosite:cn` / `geoip:cn`、广告拦截、`udp/443` 阻断 | geodata（`geoip.dat`/`geosite.dat`） |

切换到 gateway：

```sh
cp /etc/sodama/config-gateway.dae /etc/sodama/config.dae
chmod 640 /etc/sodama/config.dae
# geodata 缺失时该模板里的 geosite/geoip 规则不生效（日志会说明），其余规则正常
sed -i "s|^# *geodata_dir.*|geodata_dir: '/usr/share/v2ray'|" /etc/sodama/config.dae
/etc/init.d/sodama reload
```

### 2.3 规则集（面板/文件都可改）

默认配置带三条 `rule_set`，对应 `/etc/sodama/rules/` 下的文本文件：

| 标签 | 文件 | 作用 |
|---|---|---|
| `cn_direct` | `rules/cn_direct.txt` | 国内常用域名 → **直连**（含 `deepseek.com` / `moonshot.cn` / `bigmodel.cn` 等国产 AI API） |
| `user_proxy` | `rules/user_proxy.txt` | 你强制走代理的域名 |
| `user_direct` | `rules/user_direct.txt` | 你强制直连的域名 |

格式：每行一条，`#` 注释；裸条目 = 域名后缀（含子域），也支持 `full:` / `suffix:` / `keyword:` / `regex:`。
**改文件保存即热生效**，不需要重启。

```sh
echo 'api.example.com' >> /etc/sodama/rules/user_direct.txt    # 立刻生效
```

> 常见需求：某个国产 API/SaaS 走代理被拒或极慢 → 加进 `user_direct.txt`；
> 想让某个海外服务固定走代理 → 加进 `user_proxy.txt`。

### 2.4 DNS

不写 `dns` 段时，内置回退是 `8.8.8.8:53`——**部分网络不可达，表现为「能 ping 不能上网」**。
默认模板已经改用 AliDNS DoH：

```
dns {
    upstream {
        alidns: 'https://223.5.5.5/dns-query?sni=dns.alidns.com'
    }
    routing {
        request {
            qname(file: 'blocklist.txt') -> reject      # 拦截名单（可留空）
            fallback: alidns
        }
        response { fallback: accept }
    }
}
```

dnsmasq 不需要改：sodama 不占 53 端口，客户端 DNS 判断在数据面完成。

### 2.5 常用运行参数

| 键 | 建议 | 说明 |
|---|---|---|
| `dial_mode` | `ip`（默认）/ `domain` | 客户端自带 DoH/DoT 绕过本机 DNS 时，域名规则可能失效，此时用 `domain`（SNI 嗅探） |
| `check_interval` | `10s` | 节点健康探测间隔 |
| `relay_idle_timeout` | `900s` | 大模型流式响应静默期长，别设太小 |
| `watch_config` | `10` | 改配置自动热加载（inotify 为主、秒级扫描兜底） |
| `auto_config_kernel_parameter` | `true` | 自动写 `ip_forward`/`rp_filter` 等并在被改回时纠正 |

---

## 3. 拓扑与 uci 配置

`/etc/config/sodama`（procd）+ `/etc/sodama/config.dae`（分流）分工：**进程级参数走 uci，行为参数走 .dae**。

> **优先级**：init 脚本总是显式传 `--wan` / `--lan` / `--dual`，因此 **uci 值覆盖** `config.dae` 里的
> `wan_interface` / `lan_interface`。想确认当前实际钩子：`sodama status --socket /var/run/sodama.sock` 看 hooks 段。

```sh
uci show sodama                     # 看当前值
uci set sodama.main.enabled=1       # 0=装了但不自启
uci set sodama.main.wan='pppoe-wan'
uci set sodama.main.lan=''          # 留空 = --lan none（推荐，见下）
uci commit sodama
/etc/init.d/sodama start
```

### 3.1 主路由（推荐）

- `lan` 留空（`--lan none`）：**WAN 出口钩子**接管本机流量与 LAN 转发流量，规则最简、开销最低。
- `wan` 填实际 WAN 接口（PPPoE 常是 `pppoe-wan`）。
- 客户端网关 + DNS 指向本机。
- 主路由模式**不需要**给 LAN 挂 ingress 钩子（`--lan none` 即可）；只有想按 LAN 侧源地址分流时才填 `br-lan`。

### 3.2 单臂旁路由

```sh
uci set sodama.main.dual='br-lan'   # 同一接口同时挂 LAN/WAN 合用程序
uci set sodama.main.lan=''
```

客户端把网关指到旁路由；旁路由自身到主路由的默认路由必须正常（fw4 默认允许 LAN→WAN）。

### 3.3 仅代理本机（调试/试验）

```sh
uci set sodama.main.lan='none'
uci set sodama.main.wan='wan'
```

配合 `config.dae` 里 `lan_interface: none`。

---

## 4. 日常操作

```sh
/etc/init.d/sodama start | stop | restart | reload   # reload = 热重载（规则/订阅/配置）
sodama status --socket /var/run/sodama.sock          # 状态（节点/组/钩子/DNS 统计）
sodama metrics --socket /var/run/sodama.sock         # Prometheus 文本
sodama trace --socket /var/run/sodama.sock --seconds 10   # 判决事件（哪条规则命中）
logread -e sodama                                    # procd 日志（也写 /var/log/sodama.log）
/usr/lib/sodama/sodama-datapath status               # netns/veth/策略路由/sysctl
```

> **Web 面板不在 ipk 里**（面板是 wasm + 独立二进制，定位是 x86/ARM 小主机）。路由器上用上面的 CLI；
> 需要图形界面就在同网段的机器上部署面板并指向引擎 socket（或用 SSH 端口转发 + `sodama status --json` 自建）。

---

## 5. 装完验证清单（建议逐条过）

```sh
# 1) 服务与钩子
/etc/init.d/sodama status
sodama status --socket /var/run/sodama.sock | head -30      # 应看到 hooks / 节点组 / 规则数

# 2) 数据面对
/usr/lib/sodama/sodama-datapath status                       # netns daens、veth dae0、fwmark 规则

# 3) 出口 IP（从 LAN 客户端执行，或用路由器自身）
curl -s https://api.ipify.org; echo                         # 应为节点 IP，不是家宽 IP

# 4) 国内直连（默认模板应命中 cn_direct）
sodama trace --socket /var/run/sodama.sock --seconds 5      # 访问 deepseek.com 时应是 direct
curl -s -o /dev/null -w '%{http_code}\n' https://api.deepseek.com/   # 401 = 通

# 5) DNS
nslookup www.baidu.com 192.168.1.1                          # 换成你的网关地址
```

---

## 6. 排障

| 症状 | 原因 / 处理 |
|---|---|
| `ERROR: 内核/ip 不支持 netns` / `open /var/run/netns/daens: No such file` | 内核没开 `CONFIG_NAMESPACES`/`NET_NS`（官方镜像默认如此）→ 按附录 A 自编；或 `ip` 是 busybox → 装 `ip-full` |
| 启动即退出，日志 `routing 段没有任何可编译规则` | 配置里只有 `fallback:`（它不是规则）。至少留一条真实规则，如 `dip(192.168.0.0/16) -> direct` |
| `加载配置失败` / `权限 ... 过于开放` | `chmod 640 /etc/sodama/config.dae`（规则集文件同理） |
| eBPF 加载失败（verifier/attach） | 内核 <6.6，或缺 `NET_CLS_ACT/NET_CLS_BPF/NET_SCH_INGRESS/NET_XGRESS` |
| `if_nametoindex(dae0) failed` | 数据面对未建立：`sodama-datapath setup`（init 脚本已内含，失败时会拦住启动） |
| 能 ping 不能上网 / 网页打不开 | DNS 上游不可达：确认 `dns.upstream`；默认回退 `8.8.8.8` 在部分网络不通 |
| 国产 AI API（DeepSeek 等）失败或极慢 | 被代理了。确认它在 `rules/cn_direct.txt`（默认已含）或加进 `rules/user_direct.txt` |
| 换网/切 WiFi 后彻底断网 | 旧版本会劫持 DHCP 广播；升级到含「广播/组播/DHCP 一律放行」的版本 |
| 装了官方 kmod 报 vermagic 不匹配 | 自编内核时把 `VETH`/TC 相关直接 `=y` 编进镜像（附录 A 已如此） |
| 路由器内存紧张 | 稳态 ~12MB；二进制 8MB + eBPF 1MB，可放 overlay/外部存储 |
| 改了配置不生效 | `watch_config` 是否关掉？或配置被拒（`sodama validate` 看原因），失败会保留旧规则 |

---

## 7. 升级 / 卸载

```sh
# 升级（保留 /etc/config/sodama 与 /etc/sodama/*）
opkg install /tmp/sodama_<newver>_<arch>.ipk
#   /etc/sodama 下的配置与规则集不会被覆盖（postinst 只在文件缺失时复制模板）
/etc/init.d/sodama restart

# 卸载
/etc/init.d/sodama stop
opkg remove sodama
rm -rf /etc/sodama /var/log/sodama.log*     # 需要彻底清理时
```

> 内核 sysctl 不回滚（`ip_forward`、`rp_filter`），需要恢复请手动改回或重启。

---

## 8. 已知限制

- **官方镜像需自编内核**（namespace 关闭）；这是 dae 系方案的共同前提。
- **Web 面板不在 ipk 内**（见 §4 说明）。
- **UDP 默认直连**（不代理）：需要的场景请换支持 UDP 的节点，并删掉 `l4proto(udp) -> direct`；
  gateway 模板默认 `udp/443 -> block`（让浏览器回落 TCP，更稳）。
- **geodata 不自带**：`geoip.dat` / `geosite.dat` 需自行放置并在 `global.geodata_dir` 指向。
- **aarch64 真机**：二进制与对象已能交叉构建，主要验证在 x86_64（QEMU/真机）；aarch64 请先小范围试。

---

## 附录 A：内核片段（追加到 `target/linux/<target>/config-<ver>`）

完整文件见 `install/openwrt/kernel-fragment.config`。核心几项：

```
CONFIG_NAMESPACES=y
CONFIG_NET_NS=y
CONFIG_UTS_NS=y
CONFIG_VETH=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_NET_CLS_ACT=y
CONFIG_NET_CLS_BPF=y
CONFIG_NET_SCH_INGRESS=y
CONFIG_NET_ACT_BPF=y
CONFIG_BPF_STREAM_PARSER=y
CONFIG_CGROUP_BPF=y          # pname() 进程名分流（缺失自动降级）
CONFIG_DEBUG_INFO_BTF=y      # 建议，非必需
```

自编示例（x86_64，约 30–60 分钟）：

```sh
git clone -b v24.10.4 --depth 1 https://github.com/openwrt/openwrt openwrt-src && cd openwrt-src
cat >> target/linux/x86/64/config-6.6 <<'EOF'
CONFIG_NAMESPACES=y
CONFIG_UTS_NS=y
CONFIG_IPC_NS=y
CONFIG_NET_NS=y
CONFIG_VETH=y
CONFIG_NET_CLS_ACT=y
CONFIG_NET_CLS_BPF=y
CONFIG_NET_SCH_INGRESS=y
CONFIG_NET_ACT_BPF=y
CONFIG_BPF_STREAM_PARSER=y
CONFIG_CGROUP_BPF=y
EOF
cat > .config <<'EOF'
CONFIG_TARGET_x86=y
CONFIG_TARGET_x86_64=y
CONFIG_TARGET_x86_64_DEVICE_generic=y
CONFIG_KERNEL_DEBUG_INFO=y
CONFIG_KERNEL_DEBUG_INFO_BTF=y
EOF
make defconfig && make -j"$(nproc)"
```

## 附录 B：参考配置（默认模板的结构）

```
global { wan_interface wan / lan_interface br-lan / tproxy_port / auto_config_kernel_parameter }
node|subscription { … }
group { proxy { policy: min_moving_avg } }        # 用订阅时不要写 filter
rule_set { cn_direct / user_proxy / user_direct } # → /etc/sodama/rules/*.txt
routing {
    domain(ruleset: user_proxy)  -> proxy
    domain(ruleset: user_direct) -> direct
    domain(ruleset: cn_direct)   -> direct
    dip(私网/组播/保留)            -> direct
    l4proto(udp)                 -> direct
    fallback: proxy
}
dns { upstream { alidns: DoH } routing { request { blocklist → reject; fallback: alidns } } }
```
