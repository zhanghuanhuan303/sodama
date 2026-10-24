# OpenWrt 支持（P0：musl 构建 · 内核要求 · 打包 · QEMU 验证）

> **先看用户向说明：[`openwrt-guide.md`](openwrt-guide.md)** —— 安装/配置/拓扑/排障/升级，可直接转给使用者。
> 本文件是同一主题的**开发向**记录：内核开关细节、自编内核进度、QEMU 冒烟方法。

本文件是 sodama 跑在 OpenWrt 上的完整技术说明：**平台前提、交叉构建、ipk 打包、拓扑与系统集成、验证与排障**。
配套文件在 `install/openwrt/`（包与 procd/uci）与 `sodama/lab/build-openwrt.sh`、`sodama/lab/openwrt-smoke.sh`。

## 0. 一句话结论（先读）

- 运行时要求：**Linux ≥ 6.6**（TCX）+ **CONFIG_NAMESPACES/NET_NS=y** + TC/BPF 相关开关（见 §2）。
- **官方 OpenWrt 镜像（含 24.10.4）默认没有开 `CONFIG_NAMESPACES`**——实测其 generic config：
  `# CONFIG_NAMESPACES is not set`（dae 上游同样依赖 `/run/netns/daens`，因此这不是 sodama 特有要求）。
  → 想在 OpenWrt 上用 sodama，需要按 §2 的 kernel fragment **自编一次内核+镜像**（一次性成本）。
- 应用侧是**静态 musl 单文件**（x86_64/aarch64/armv7 已验证可构建），另有 ~0.5MB 的 eBPF 对象；
  内存稳态 ~12MB（见 `docs/benchmark-report.html`），很适合路由器。
- QEMU 冒烟（§5）在自编镜像上自动验证：二进制运行 → veth/netns/datapath → eBPF 加载/TCX 挂载 → status。

## 0.1 当前进度（2026-10-05：P0 应用侧已完成，自编内核冒烟阶段暂停）

- ✅ **已完成**：
  - musl 静态交叉构建（x86_64/aarch64/armv7，`sodama/lab/build-openwrt.sh`）；
  - ipk 预编译包（`install/openwrt/`：Makefile/procd/uci/数据面对 helper）；
  - 内核 fragment（`install/openwrt/kernel-fragment.config`）与平台要求文档（本文件）；
  - 官方镜像 QEMU 冒烟（`sodama/lab/openwrt-smoke.sh`）：跑通「ipk 安装 → 二进制运行 → 数据面报错定位」，
    并**实测确认官方内核缺 `CONFIG_NAMESPACES`**；脚本已支持 `OPENWRT_IMG=` 指向自定义镜像。
- ⏸️ **暂停（移到后续阶段）**：自编内核镜像上的完整 eBPF 冒烟。
  - 源码/构建目录留在 `<openwrt-build-dir>`（~1.1GB，v24.10.4）。
  - **已定位构建宿主问题**（与 sodama 无关）：Arch/GCC 15 下 `tools/cmake 3.30.5` bootstrap 链接失败
    （`cmGlobalGhsMultiGenerator` 未定义）。最小补丁（已验证预处理/编译思路）：删除 `Source/cmake.cxx` 中
    GHS 的 include 与 `NewFactory()` 注册两行，固化为 `tools/cmake/patches/161-*.patch`。
  - 恢复步骤：应用补丁 → `make -j$(nproc)` → `bin/targets/x86/64/*ext4-combined.img.gz` →
    `OPENWRT_IMG=<img> sodama/lab/openwrt-smoke.sh`。
- 后续：aarch64 真机验证；SDK 内出 ipk 一键化。

## 1. 交付物与快速开始

```bash
# ① 开发机构建 musl 产物（需要 rustup target + zig + cargo-zigbuild）
sodama/lab/build-openwrt.sh --arch aarch64                       # 或 x86_64 / armv7 / all
# 产物：build/openwrt/aarch64/{sodama,sodama-ebpf,SHA256SUMS}

# ② 在 OpenWrt SDK 里出 ipk（预编译产物版包）
cp -r install/openwrt <sdk>/package/sodama
cd <sdk> && sodama/lab/build-openwrt.sh --arch aarch64 --sdk-payload <你自己仓库路径>/install/openwrt
make package/sodama/compile V=s
#   → bin/packages/<arch>/base/sodama_0.1.0-1_<arch>.ipk

# ③ 设备上
opkg install sodama_*.ipk
vi /etc/sodama/config.dae        # 换成你的节点（或改 procd 参数用 --subscribe）
uci set sodama.main.enabled=1 && uci commit
/etc/init.d/sodama start
sodama status --socket /var/run/sodama.sock | head    # 看 hooks/规则
```

手动部署（不用 ipk）也可以：把 `sodama` 放 `/usr/bin/`、`sodama-ebpf` 放 `/usr/lib/sodama/`，
用 `files/sodama-datapath` 建数据面对后直接跑 loader（见 §5 的 guest 脚本）。

## 2. 内核要求（自编内核用 fragment）

`install/openwrt/kernel-fragment.config` 是要追加到 OpenWrt 的
`target/linux/x86/64/config-<ver>`（或对应 target）末尾的片段：

| 组 | 开关 | 原因 |
|---|---|---|
| eBPF | `BPF_SYSCALL`（24.10 已 y）、`BPF_JIT`（已 y） | 加载/执行 eBPF |
| **netns** | **`NAMESPACES=y`、`NET_NS=y`、`UTS_NS=y`（建议 IPC_NS）** | **控制面对 `daens` netns + tproxy 监听（官方镜像默认关！）** |
| TC/TCX | `NET_CLS_ACT`、`NET_CLS_BPF`、`NET_SCH_INGRESS`、`NET_ACT_BPF`（`NET_XGRESS` 会自动 y） | clsact + TCX 挂载（内核 ≥6.6） |
| sockmap | `BPF_STREAM_PARSER`（`NET_SOCK_MSG` 已 y） | offload/sockmap 路径 |
| cgroup2 | `CGROUP_BPF` | `pname()` 进程名分流（缺失则自动降级，非致命） |
| veth | `VETH=y`（或 kmod-veth） | 控制面对 dae0/dae0peer |
| 建议 | `KERNEL_DEBUG_INFO_BTF=y`（OpenWrt 构建选项） | 调试/未来 CO-RE；当前程序不依赖，非必需 |

自编示例（x86_64，一次性 ~30–60 分钟）：

```bash
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
make defconfig && make -j$(nproc)
# 产物在 bin/targets/x86/64/*.img.gz
```

`sodama/lab/openwrt-smoke.sh` 就是按这套流程编出镜像后自动跑冒烟的（附完整示例脚本）。

## 3. 拓扑与系统集成

### 3.1 主路由（推荐）

- WAN 口（`wan` / `pppoe-wan`）在数据面钩住即可：procd 默认 `lan=none → --lan none --wan <wan>`，
  本机与 LAN 转发流量都会在 WAN egress 被分流（与 `lab/gateway.sh` 真网关模式一致）。
- 数据面对（netns/veth/静态邻居/策略路由/sysctl）由 `sodama-datapath` 建立，procd 起停自动管理。

### 3.2 单臂旁路由

- uci 设 `option dual 'br-lan'`（单接口 dual-role 程序），客户端网关指向本机。
- 需要保证「旁路由 → 主路由」的默认路由正常；fw4 默认允许 LAN→WAN。

### 3.3 DNS / dnsmasq / odhcpd

- sodama **不占用 53 端口**：客户端 DNS 在数据面被截获并按其 DNS 策略转发（内部监听/ sockmap 路径）。
  dnsmasq 继续服务路由器自身与 DHCP 下发的解析，两者不冲突。
- 如希望路由器自身（dnsmasq 的上游）也走代理，把 dnsmasq upstream 指到规则命中 proxy 的地址即可（可选）。

### 3.4 fw4 / nftables / sysctl

- 数据面走 eBPF（tc/TCX），**不依赖 nft/iptables tproxy 规则**；fw4 保持默认即可。
- `sodama-datapath` 会设置：`ip_forward=1`、`rp_filter=0`（all/default）、`dae0.accept_local=1`、
  netns 内 `accept_local/ip_nonlocal_bind` 与 `fwmark 0x8000000 → table 2023 local` 规则（对照 dae）。

## 4. 打包说明

| 文件 | 说明 |
|---|---|
| `install/openwrt/Makefile` | 安装预编译产物 + 初始化脚本 + uci 配置 + 示例配置；`DEPENDS:=+ip-full +kmod-veth` |
| `install/openwrt/files/sodama.init` | procd：start=setup+loader、stop=teardown、reload=`sodama reload`；respawn 守护 |
| `install/openwrt/files/sodama-datapath` | 数据面对建立/回收（对照 `sodama/lab/gateway.sh`） |
| `install/openwrt/files/sodama.config` | `/etc/config/sodama`（enabled/config/lan/wan/dual/status_socket/…） |
| `install/openwrt/files/config.example.dae` | `/usr/share/sodama/config.example.dae`（min profile，校验通过） |
| `install/openwrt/files/config.gateway.dae` | `/usr/share/sodama/config.gateway.dae`（gateway profile，需 geodata） |
| `install/openwrt/files/rules/*.txt`、`blocklist.txt` | 规则集（`cn_direct`/`user_proxy`/`user_direct`）与 DNS 拦截名单 |
| `install/openwrt/files/sync-config.sh` | 从 `packaging/arch/` 同步上述资产（`--check` 供发布门禁） |
| `install/openwrt/files/README.md` | 安装到 `/usr/share/sodama/README.md`（= `docs/openwrt-guide.md`） |
| `install/openwrt/kernel-fragment.config` | 内核开关片段（§2） |

> 若在 buildroot 里从源码构建（非预编译），把仓库作为 `package/sodama` 并按 OpenWrt 的 rust-package
> 约定写 `Build/Compile` 即可；本仓库当前提供的是预编译路线（可复现、免在 SDK 里拉夜版 Rust 工具链）。

## 5. QEMU 冒烟（自动化）

```bash
sudo sodama/lab/openwrt-smoke.sh          # 首次自动下载官方镜像/ipk；构建自定义内核镜像后推荐指向它
# 自定义镜像：OPENWRT_IMG=/path/to/custom.img sudo sodama/lab/openwrt-smoke.sh
```

冒烟内容（guest 内脚本，root 控制台自动执行）：

1. `uname -a` / `/sys/kernel/btf` / cgroup2 挂载检查；
2. 离线安装 `ip-full`（+官方镜像时的 kmod 包）；
3. 建 veth → `sodama-datapath setup` → 启动 loader（`--lan none --wan veth0 --dialer direct`）；
4. `sodama status` 输出 hooks/版本/规则，日志尾部归档；
5. 汇总 PASS/FAIL（日志 `/tmp/owrt-smoke.log`）。

## 6. 排障

| 症状 | 原因/处理 |
|---|---|
| `ERROR: 内核/ip 不支持 netns`、`open /var/run/netns/daens: No such file` | 内核缺 `CONFIG_NAMESPACES/NET_NS`（官方镜像默认如此）→ 按 §2 自编；或 `ip` 仍是 busybox（装 `ip-full`） |
| eBPF 加载失败（verifier/attach） | 内核 <6.6（无 TCX）或缺 `NET_CLS_ACT/NET_CLS_BPF/NET_SCH_INGRESS`；核对 §2 |
| `if_nametoindex(dae0) failed` | 数据面对未建立：先 `sodama-datapath setup`（init 脚本已内含） |
| 代理生效但 DNS 异常 | 检查 DNS 段配置与上游可达；dnsmasq 无需改动；可用 `sodama status`/日志核对 DNS 策略 |
| 装了官方 kmod 报版本不匹配 | kmod 的 vermagic 必须与内核构建一致——自编内核时把 VETH/TC 直接 `=y` 编进镜像（fragment 已如此） |
| 路由器内存紧张 | 稳态 ~12MB、eBPF 对象 0.5MB；二进制 ~6–7MB（musl 静态），可放 overlay/外部存储 |

## 7. 与 dae（Go）对照

- dae 上游同样使用固定 netns（`/run/netns/daens`），因此**在 OpenWrt 上同样需要开 NET_NS 的内核**；
  这是 dae 系产品的部署前提，不是 sodama 引入的新约束。
- sodama 额外优势：单文件 musl 静态（无动态依赖）、内存/线程占用更低（见内存终测报告）、
  TCX bpf_link 退出即摘钩（无 tc filter 残留）。
