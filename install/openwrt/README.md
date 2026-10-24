# sodama · OpenWrt 包

预编译产物版 OpenWrt 包（musl 静态二进制 + eBPF 对象 + procd 初始化 + uci 配置 + 配置模板/规则集）。

- **用户向说明**：[`docs/openwrt-guide.md`](../../docs/openwrt-guide.md)（也随包装到 `/usr/share/sodama/README.md`）
- 开发向细节（内核开关/自编内核/QEMU 冒烟）：[`docs/openwrt.md`](../../docs/openwrt.md)

> 包内 `files/config.example.dae`、`files/config.gateway.dae`、`files/blocklist.txt`、`files/rules/*.txt`
> 由 `files/sync-config.sh` 从 `packaging/arch/` 生成（唯一事实来源）；改了那边记得：
> `sh install/openwrt/files/sync-config.sh`，`make-release.sh` 会校验是否同步。

## 1. 准备产物（在开发机）

```bash
# 需要：rustup 目标 + zig（cargo-zigbuild）；脚本会自动检查
sodama/lab/build-openwrt.sh --arch aarch64 --sdk-payload .   # 或 --arch x86_64 / armv7
# 产物：prebuilt/sodama  prebuilt/sodama-ebpf
```

## 2. 在 OpenWrt SDK 里出 ipk

```bash
cp -r install/openwrt <sdk>/package/sodama
cd <sdk>
make package/sodama/compile V=s
# 产出：bin/packages/<arch>/base/sodama_1.0.0-2_<arch>.ipk
```

## 3. 设备上安装与启用

```bash
opkg install sodama_*.ipk
vi /etc/sodama/config.dae          # 换成你的节点/订阅
uci set sodama.main.enabled=1
uci commit sodama
/etc/init.d/sodama start
# 热重载：/etc/init.d/sodama reload
# 状态：  sodama status --socket /var/run/sodama.sock
```

## 文件

| 文件 | 作用 |
|---|---|
| `Makefile` | OpenWrt 包定义（安装预编译产物） |
| `files/sodama-datapath` | netns/veth/地址/静态邻居/sysctl 的数据面对（对照 `lab/gateway.sh`） |
| `files/sodama.init` | procd 脚本（setup → loader；stop → teardown；reload → `sodama reload`） |
| `files/sodama.config` | `/etc/config/sodama` 默认值 |
| `files/config.example.dae` | `/usr/share/sodama/config.example.dae`（min profile；接口默认 `wan`/`br-lan`） |
| `files/config.gateway.dae` | `/usr/share/sodama/config.gateway.dae`（gateway profile，需 geodata） |
| `files/rules/*.txt`、`files/blocklist.txt` | 规则集（`cn_direct`/`user_proxy`/`user_direct`）与 DNS 拦截名单 |
| `files/README.md` | 安装到 `/usr/share/sodama/README.md`（= `docs/openwrt-guide.md`） |
| `files/sync-config.sh` | 从 `packaging/arch/` 同步上述资产（`--check` 供发布门禁） |
| `kernel-fragment.config` | 内核配置要求（BPF/TCX/TC/cgroup2/netns/veth） |
