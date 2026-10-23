#!/usr/bin/env bash
# 生成「Arch 内测包」：预编译的 .pkg.tar.zst + 交互安装/卸载脚本 + 说明，打成一个文件，
# 直接发给帮忙测试的人（不需要 GitHub Release，也不需要 AUR，不需要编译）。
#
# 用法：
#   packaging/make-beta-bundle.sh [版本]           # 复用 dist/ 里已有的 tarball
#   packaging/make-beta-bundle.sh [版本] --build    # 先跑 make-release.sh 重新构建
# 产物：
#   dist/sodama-<ver>-arch-beta.tar.gz
#
# 本脚本只用于**发布前内测**；正式发布仍走 `make-release.sh` + GitHub Release + AUR。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_VER="$(grep -m1 '^version' "$ROOT/sodama/loader/Cargo.toml" | cut -d'"' -f2)"
VER="$DEFAULT_VER"
DO_BUILD=0
for a in "$@"; do
  case "$a" in
    --build) DO_BUILD=1 ;;
    -*) echo "未知参数：$a" >&2; exit 2 ;;
    *) VER="$a" ;;
  esac
done

if [[ "$(id -u)" -eq 0 ]]; then
  echo "makepkg 不能以 root 运行；用普通用户执行本脚本（内部会调 makepkg）" >&2
  exit 1
fi

DIST="$ROOT/dist"
TARBALL="sodama-$VER-x86_64.tar.gz"
BUNDLE_NAME="sodama-$VER-arch-beta"
BUNDLE="$DIST/$BUNDLE_NAME"
STAGE="$DIST/.beta-stage-$VER"

[[ "$DO_BUILD" == 1 ]] && sh "$ROOT/packaging/make-release.sh" "$VER"

if [[ ! -f "$DIST/$TARBALL" ]]; then
  echo "缺少 $DIST/$TARBALL；先跑 packaging/make-release.sh 或加 --build" >&2
  exit 1
fi

SHA="$(sha256sum "$DIST/$TARBALL" | cut -d' ' -f1)"

echo "== 1/4 用正式 PKGBUILD 构建二进制包（本地 source，不联网） =="
rm -rf "$STAGE" "$BUNDLE" "$DIST/$BUNDLE_NAME.tar.gz"
install -d "$STAGE"
cp "$DIST/$TARBALL" "$STAGE/$TARBALL"
sed -e "s|^source=.*|source=(\"$TARBALL\")|" \
    -e "s|^sha256sums=.*|sha256sums=('$SHA')|" \
    "$ROOT/packaging/aur/sodama-bin/PKGBUILD" >"$STAGE/PKGBUILD"
cp "$ROOT/packaging/aur/sodama-bin/"*.install "$STAGE/"
( cd "$STAGE" && makepkg -f >/dev/null )
PKG="$(find "$STAGE" -maxdepth 1 -name 'sodama-bin-*.pkg.tar.zst' -print -quit)"
[[ -n "$PKG" ]] || { echo "makepkg 没有产出 .pkg.tar.zst" >&2; exit 1; }
PKGBASE="$(basename "$PKG")"
echo "   $PKGBASE"

echo "== 2/4 组装内测包 =="
install -d "$BUNDLE"
cp "$PKG" "$BUNDLE/$PKGBASE"
( cd "$BUNDLE" && sha256sum "$PKGBASE" >"$PKGBASE.sha256" )
install -m755 "$ROOT/packaging/beta/install.sh" "$BUNDLE/install.sh"
install -m755 "$ROOT/packaging/beta/uninstall.sh" "$BUNDLE/uninstall.sh"
PKGSHA="$(cut -d' ' -f1 <"$BUNDLE/$PKGBASE.sha256")"

echo "== 3/4 安装说明 =="
cat >"$BUNDLE/INSTALL.md" <<EOF
# sodama $VER · Arch Linux 内测包

> 预编译包，**不联网、不编译**；装完由 \`pacman\` 追踪，可干净卸载。
> **别装到容器里**：需要 \`CAP_BPF\` / \`CAP_NET_ADMIN\` / netns。

## 三十秒版本

\`\`\`bash
tar xzf $BUNDLE_NAME.tar.gz && cd $BUNDLE_NAME
sudo bash install.sh          # 交互式：自检 → 装包 → 选网卡 → 填订阅 → 校验 → 启动
\`\`\`

装完浏览器打开 \`http://<本机 IP>:8080\`（选了面板的话），或直接 \`curl https://api.ipify.org\` 看出口 IP 有没有变。

## 包内文件

| 文件 | 用途 |
|---|---|
| \`$PKGBASE\` | 预编译 pacman 包（引擎 + eBPF 对象 + systemd 单元 + 面板 + 配置模板） |
| \`$PKGBASE.sha256\` | 校验和 |
| \`install.sh\` | 交互安装（也支持 \`--check\` / \`--yes\` / \`--uninstall\`） |
| \`uninstall.sh\` | 干净卸载（停服务 → 清拓扑 → \`pacman -R\` → 可选删配置） |
| \`INSTALL.md\` | 本文件 |

sha256：\`$PKGSHA\`

## 交互安装会问你什么

1. **WAN 网卡**——默认填默认路由所在网卡（\`ip route show default\`），回车即用。
2. **LAN 网卡**——默认填探测到的网桥（\`br0\`/\`br-lan\`…）；**只代理本机就填 \`none\`**。
   填错会导致 LAN 设备上不了网，但本机不受影响。
3. **出口节点**：
   - 选 1 → 粘订阅链接（\`https://…\`），节点自动更新；
   - 选 2 → 粘单个节点链接（\`vless://\` / \`ss://\` / \`trojan://\` / \`socks5://\` …）；
   - 选 3 → 跳过，稍后自己改 \`/etc/sodama/config.dae\`。
4. **Web 面板**：是否启用；监听 \`0.0.0.0:8080\`（局域网）还是 \`127.0.0.1:8080\`（仅本机）；可选 token。
5. **是否现在启动**。

写入配置前会自动备份为 \`/etc/sodama/config.dae.bak-<时间戳>\`；写入后自动跑 \`sodama validate\`，
**校验不过会自动回滚**。

> 已有自定义配置（不含模板占位节点）时脚本**不会改你的配置**，只装包。要强制重新引导：
> \`sudo bash install.sh --force-config\`。

## 无人值守 / 自定义

\`\`\`bash
sudo bash install.sh --check                      # 只自检，不动系统
sudo bash install.sh --yes \\\\
    --wan enp1s0 --lan br0 \\\\
    --sub 'https://example.com/sub?token=xxx' \\\\
    --panel --bind 0.0.0.0:8080 --token 'my-secret' \\\\
    --start
# 单节点 + 单机模式
sudo bash install.sh --yes --wan enp1s0 --lan none --node 'vless://uuid@host:443?security=tls#hk'
\`\`\`

参数：\`--wan\` \`--lan\` \`--sub\` \`--node\` \`--panel/--no-panel\` \`--bind\` \`--token\` \`--start/--no-start\` \`--force-config\`。

## 手动安装（不用脚本）

\`\`\`bash
sha256sum -c $PKGBASE.sha256
sudo pacman -U ./$PKGBASE                  # 本地文件，不走仓库、不需要 AUR helper/base-devel
sudo \$EDITOR /etc/sodama/config.dae        # wan_interface / lan_interface + node{} 或 subscription{}
sudo chmod 640 /etc/sodama/config.dae      # 权限硬要求：放宽了拒绝启动
sudo sodama validate /etc/sodama/config.dae
sudo systemctl enable --now sodama
# 面板默认仅本机监听：sudo systemctl enable --now sodama-panel → http://127.0.0.1:8080
# 需要局域网访问：panel.conf 里 bind = 0.0.0.0:8080（并建议设 token）
\`\`\`

配置里出口二选一（**订阅是「键 = 标签，值 = URL」**）：

\`\`\`
node { my: 'vless://uuid@host:443?security=tls&sni=example.com#node1' }
# 或
subscription { main: 'https://example.com/sub' }
\`\`\`

## 装完自检

\`\`\`bash
systemctl status sodama                  # Type=notify：READY 之后才算起来
journalctl -u sodama -b -f               # 日志（同时写 /var/log/sodama.log）
curl -s https://api.ipify.org; echo      # 出口 IP 应变成节点 IP
sodama status --socket /run/sodama/status.sock --json | jq .   # 节点/组/连接
sudo /usr/lib/sodama/datapath status     # netns/veth/策略路由/sysctl
\`\`\`

## 常用命令

\`\`\`bash
sudo systemctl reload sodama             # 改完配置热重载（不断流）
sudo systemctl restart sodama            # 重建数据面（短暂断流）
sodama metrics --socket /run/sodama/status.sock                # Prometheus 文本
sodama trace --socket /run/sodama/status.sock --seconds 10     # 判决事件
sudo sodama sysdump --socket /run/sodama/status.sock --out /tmp/sodama-dump.tar.gz
\`\`\`

## 排障

| 现象 | 处理 |
|---|---|
| \`加载配置失败\` / 启动即退出 | \`sodama validate\`；确认 \`chmod 640\` |
| \`netns daens 不存在\` | \`sudo /usr/lib/sodama/datapath setup\`；\`journalctl -u sodama -b\` 看 ExecStartPre |
| 加载 eBPF 失败（权限/verifier） | \`ls /sys/kernel/btf/vmlinux\`；\`dmesg \\| tail\` 看 verifier 日志 |
| 没有流量 / 节点全不可用 | \`sodama status --json \\| jq '.group'\`；节点 URL、本机时间、能否直连节点 |
| 本机能通、LAN 设备不能 | 网关/DNS 是否指向本机；\`lan_interface\` 是否填对；\`datapath status\` |
| 面板打不开 | \`ss -ltnp \\| grep 8080\`；\`bind\` 配置；防火墙 |
| 停止后网络异常 | \`sudo /usr/lib/sodama/datapath teardown\`（\`kill -9\` 时 ExecStopPost 没跑） |
| 内核 <6.6 | 回退 \`cls_bpf\` 挂载，功能可用、特性略降 |
| \`Failed to execute /usr/lib/sodama/datapath: Exec format error\`（203/EXEC） | 仅 \`1.0.0-1\` 及更早的包：\`datapath\` 缺 shebang。升级到 \`1.0.0-2+\`；应急：\`sudo sed -i '1i #!/bin/sh' /usr/lib/sodama/datapath\` 后 \`systemctl start sodama\` |
| 面板 = active 但代理不通 | 面板 \`Requires=sodama.service\`，正常不会出现；若看到，先 \`systemctl status sodama\` |

完整说明：\`/usr/share/doc/sodama/README.md\`（§11「内测分发」是维护者向章节，忽略即可）；
配置全集：\`/usr/share/doc/sodama/config-reference.md\`。

## 请回报什么

**成功也请回报**：

- \`uname -r\` + 内核包（\`linux\` / \`linux-lts\` / \`linux-zen\` / \`linux-hardened\`）
- \`sodama --version\`
- 安装方式（交互脚本 / \`--yes\` / 手动 pacman）
- 拓扑：网关模式还是单机；\`lan_interface\` 填的什么
- 结果：出口 IP 是否变化、DNS 是否正常、面板能否打开

**失败时附**：

\`\`\`bash
journalctl -u sodama -b --no-pager | tail -100
sudo sodama sysdump --socket /run/sodama/status.sock --out /tmp/sodama-dump.tar.gz
sudo /usr/lib/sodama/datapath status
\`\`\`

## 升级 / 卸载

\`\`\`bash
sudo bash install.sh                    # 拿到新包后重跑：停服务 → 装包 → 保留配置
sudo bash install.sh --uninstall        # 干净卸载：停服务 → 清 netns/veth → pacman -R
sudo bash uninstall.sh --purge -y       # 连 /etc 配置与日志一起删
sudo bash uninstall.sh --dry-run        # 先看会做什么，不动手
\`\`\`

卸载**不**回滚内核 sysctl（\`ip_forward\`、\`rp_filter\`），需要的话手动恢复或重启。
EOF

echo "== 4/4 打成一个文件 =="
rm -rf "$STAGE"
( cd "$DIST" && tar --owner=0 --group=0 --numeric-owner -cf - "$BUNDLE_NAME" | gzip -9n >"$BUNDLE_NAME.tar.gz" )
( cd "$DIST" && sha256sum "$BUNDLE_NAME.tar.gz" >"$BUNDLE_NAME.tar.gz.sha256" )

echo
echo "== 产物 =="
ls -lh "$DIST/$BUNDLE_NAME.tar.gz" "$DIST/$BUNDLE_NAME.tar.gz.sha256"
cat "$DIST/$BUNDLE_NAME.tar.gz.sha256"
echo
echo "把 dist/$BUNDLE_NAME.tar.gz 发给测试者即可（内含 pacman 包 + install.sh + uninstall.sh + INSTALL.md）。"
