#!/usr/bin/env bash
# sodama 内测安装脚本（Arch Linux, x86_64）—— 交互式
#
#   sudo bash install.sh                  # 引导式：自检 → 装包 → 选网卡 → 填订阅/节点 → 校验 → 启动
#   sudo bash install.sh --check          # 只做环境自检（不需要 root）
#   sudo bash install.sh --uninstall      # 等同 uninstall.sh
#   sudo bash install.sh --yes --sub URL  # 全自动（无人值守）
#
# 非交互参数（配合 --yes）：
#   --wan IF        WAN 网卡（默认 = 默认路由所在网卡）
#   --lan IF|none   LAN 网卡（默认 = 探测到的网桥，否则 none = 单机模式）
#   --sub URL       订阅链接（https://… / http-file://… / 本地文件）
#   --node URL      单节点链接（vless:// ss:// trojan:// socks5:// …）
#   --panel / --no-panel       是否启用 Web 面板（默认询问）
#   --bind ADDR     面板监听地址（交互默认按选择；--yes 默认 127.0.0.1:8080）
#   --token T       面板访问 token（默认空 = 免认证）
#   --start / --no-start       是否立即启动（默认询问）
#   --force-config  即使配置已被自定义，也重新引导写入
#
# 行为约定：
#   - 只装本地 .pkg.tar.zst（不联网、不编译、不用 AUR helper）；
#   - 改配置前备份为 config.dae.bak-<时间戳>，validate 失败自动回滚；
#   - 检测到已自定义的配置时默认不写入（除非 --force-config），避免覆盖节点。
set -euo pipefail

HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
ORIG_ARGS=("$@")
MODE=install
ASSUME_YES=0
FORCE_CFG=0
WAN="" LAN="" SUB="" NODE="" BIND="" TOKEN=""
PANEL="" START=""
PANEL_ON=0

while (($#)); do
  case "$1" in
    --check) MODE=check ;;
    --uninstall | --dry-run | --purge | --all) MODE=uninstall ;;
    -y | --yes) ASSUME_YES=1 ;;
    --force-config) FORCE_CFG=1 ;;
    --wan) WAN="${2:?--wan 需要参数}"; shift ;;
    --lan) LAN="${2:?--lan 需要参数}"; shift ;;
    --sub) SUB="${2:?--sub 需要参数}"; shift ;;
    --node) NODE="${2:?--node 需要参数}"; shift ;;
    --panel) PANEL=1 ;;
    --no-panel) PANEL=0 ;;
    --bind) BIND="${2:?--bind 需要参数}"; shift ;;
    --token) TOKEN="${2:?--token 需要参数}"; shift ;;
    --start) START=1 ;;
    --no-start) START=0 ;;
    -h | --help)
      sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      printf '未知参数：%s（-h 看用法）\n' "$1" >&2
      exit 2
      ;;
  esac
  shift
done

# --uninstall 交给独立脚本（包被移除后它仍可用），透传其余参数
do_uninstall_handoff() {
  [[ -f "$HERE/uninstall.sh" ]] || die "找不到 $HERE/uninstall.sh"
  local passthru=() a
  for a in "${ORIG_ARGS[@]}"; do [[ "$a" == --uninstall ]] || passthru+=("$a"); done
  exec bash "$HERE/uninstall.sh" ${passthru[@]+"${passthru[@]}"}
}

die() { printf '✗ %s\n' "$*" >&2; exit 1; }
ok() { printf '✓ %s\n' "$*"; }
warn() { printf '! %s\n' "$*" >&2; }

hr() { printf '\n────────────────────────────────────────────────\n'; }

if [[ "$MODE" == uninstall ]]; then
  do_uninstall_handoff
fi

# ---------------------------------------------------------------- 交互原语
ask() { # 提示 默认值 -> stdout 答案
  local prompt="$1" def="${2-}" ans
  if ((ASSUME_YES)); then printf '%s\n' "$def"; return 0; fi
  if [[ -n "$def" ]]; then printf '  %s [%s]: ' "$prompt" "$def" >&2; else printf '  %s: ' "$prompt" >&2; fi
  IFS= read -r ans || ans=""
  printf '%s\n' "${ans:-$def}"
}

ask_yn() { # 提示 默认(y|n) -> 0=yes
  local prompt="$1" def="$2" ans hint
  if ((ASSUME_YES)); then [[ "$def" == y ]]; return; fi
  if [[ "$def" == y ]]; then hint="[Y/n]"; else hint="[y/N]"; fi
  while :; do
    printf '  %s %s: ' "$prompt" "$hint" >&2
    IFS= read -r ans || ans=""
    ans="${ans:-$def}"
    case "${ans,,}" in
      y | yes) return 0 ;;
      n | no) return 1 ;;
      *) warn "请回答 y 或 n" ;;
    esac
  done
}

# ---------------------------------------------------------------- 环境自检
check_env() {
  [[ -f /etc/arch-release ]] || die "这不是 Arch Linux（缺 /etc/arch-release）"
  [[ "$(uname -m)" == x86_64 ]] || die "包是 x86_64 的，当前是 $(uname -m)"
  command -v pacman >/dev/null || die "找不到 pacman"
  [[ -f /.dockerenv || -f /run/.containerenv ]] &&
    die "检测到容器环境；sodama 需要 CAP_BPF / CAP_NET_ADMIN / netns，请装到宿主机"
  [[ -e /sys/kernel/btf/vmlinux ]] || die "内核缺 BTF（/sys/kernel/btf/vmlinux）；换官方内核再试"

  local ver major minor
  ver="$(uname -r)"
  major="${ver%%.*}"
  minor="$(printf '%s' "${ver#*.}" | cut -d. -f1)"
  ((major > 5 || (major == 5 && minor >= 17))) ||
    die "内核 $ver 太旧；需要 ≥5.17（推荐 ≥6.6 走 TCX）"
  ok "内核 $ver（≥5.17，BTF 就绪）"

  local ktype="unknown" p
  for p in linux linux-lts linux-zen linux-hardened linux-rt; do
    if pacman -Qq "$p" >/dev/null 2>&1; then
      ktype="$(pacman -Q "$p")"
      break
    fi
  done
  ok "内核包：$ktype"
  if ((major < 6 || (major == 6 && minor < 6))); then
    warn "内核 <6.6：回退 cls_bpf 挂载（功能可用，特性略降）"
  fi

  command -v systemctl >/dev/null || die "没有 systemd；本包依赖 systemd 单元"
  ok "systemd $(systemctl --version | head -1 | awk '{print $2}')"
}

# ---------------------------------------------------------------- 找包并校验
PKG=""
find_pkg() {
  local cand
  cand="$(find "$HERE" -maxdepth 1 -name 'sodama-bin-*.pkg.tar.zst' -type f | sort | head -1)"
  [[ -n "$cand" ]] || die "本目录没有 sodama-bin-*.pkg.tar.zst；先解包内测包再运行"
  PKG="$cand"
  ok "安装包：$(basename "$PKG")"
}

verify_pkg() {
  find_pkg
  if [[ -f "$PKG.sha256" ]]; then
    ( cd "$HERE" && sha256sum -c "$(basename "$PKG").sha256" ) || die "sha256 校验失败，包可能损坏"
  else
    warn "没有 .sha256，跳过校验"
  fi
  bsdtar tf "$PKG" | grep -q '^usr/lib/sodama/sodama-ebpf$' || die "包内缺 sodama-ebpf，包不对"
  ok "包内容检查通过"
}

# ---------------------------------------------------------------- 网卡探测
detect_wan() {
  ip route show default 2>/dev/null |
    awk '/^default/ { for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }'
}
detect_lan() {
  local c
  for c in br0 br-lan br-lan.1 lan; do
    if ip link show dev "$c" >/dev/null 2>&1; then echo "$c"; return 0; fi
  done
  c="$(ip -br link show type bridge 2>/dev/null | awk 'NR==1{print $1}')"
  if [[ -n "$c" ]]; then echo "$c"; else echo none; fi
}
lan_ip() {
  ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}'
}

# ---------------------------------------------------------------- 配置改写
cfg_set_global() { # 文件 key value（global 段内，缺则补）
  local cfg="$1" k="$2" v="$3" tmp
  tmp="$(mktemp)"
  awk -v k="$k" -v v="$v" '
    /^[[:space:]]*global[[:space:]]*\{/ { ing = 1; print; next }
    ing && /^[[:space:]]*\}/ {
      if (!done) printf "    %s: %s\n", k, v
      ing = 0; print; next
    }
    ing && $0 ~ ("^[[:space:]]*" k "[[:space:]]*:") {
      match($0, /^[[:space:]]*/)
      printf "%s%s: %s\n", substr($0, 1, RLENGTH), k, v
      done = 1; next
    }
    { print }
  ' "$cfg" >"$tmp"
  cat "$tmp" >"$cfg"
  rm -f "$tmp"
}

cfg_replace_section() { # 文件 section 替换内容文件
  local cfg="$1" sec="$2" repl="$3" tmp
  tmp="$(mktemp)"
  if grep -qE "^[[:space:]]*${sec}[[:space:]]*\{" "$cfg"; then
    awk -v sec="$sec" -v replfile="$repl" '
      BEGIN { n = 0; while ((getline l < replfile) > 0) lines[++n] = l; close(replfile) }
      $0 ~ ("^[[:space:]]*" sec "[[:space:]]*\\{") {
        for (i = 1; i <= n; i++) print lines[i]
        skip = 1; next
      }
      skip == 1 { if ($0 ~ /^[[:space:]]*\}/) skip = 0; next }
      { print }
    ' "$cfg" >"$tmp"
  else
    cat "$cfg" >"$tmp"
    printf '\n' >>"$tmp"
    cat "$repl" >>"$tmp"
  fi
  cat "$tmp" >"$cfg"
  rm -f "$tmp"
}

cfg_delete_section() { # 文件 section（整块删除，包括内部行）
  local cfg="$1" sec="$2" tmp
  tmp="$(mktemp)"
  awk -v sec="$sec" '
    $0 ~ ("^[[:space:]]*" sec "[[:space:]]*\\{") { skip = 1; next }
    skip == 1 { if ($0 ~ /^[[:space:]]*\}/) skip = 0; next }
    { print }
  ' "$cfg" >"$tmp"
  cat "$tmp" >"$cfg"
  rm -f "$tmp"
}

cfg_set_kv() { # 文件 key value（key = value 形式，如 panel.conf）
  local cfg="$1" k="$2" v="$3" tmp
  tmp="$(mktemp)"
  awk -v k="$k" -v v="$v" '
    $0 ~ ("^[[:space:]]*" k "[[:space:]]*=") { printf "%s = %s\n", k, v; done = 1; next }
    { print }
    END { if (!done) printf "%s = %s\n", k, v }
  ' "$cfg" >"$tmp"
  cat "$tmp" >"$cfg"
  rm -f "$tmp"
}

valid_node() {
  [[ "$1" =~ ^(vless|vmess|ss|ssr|ssd|trojan|socks5|socks4|http|https|hysteria2|hy2|tuic|anytls|wireguard|wg|juicity|ssh|mieru):// ]]
}
valid_sub() {
  [[ "$1" =~ ^(https?|https?-file|file):// ]] || [[ -f "$1" ]]
}

# ---------------------------------------------------------------- 引导配置

# 旧版出厂模板的 routing 只有 fallback（不是规则），引擎会拒启。
# 升级场景（config.dae 是 pacman backup，不会被覆盖）就地修复：补默认直连规则。
ensure_routing_rules() {
  local cfg=/etc/sodama/config.dae out tmp
  out="$(sodama validate "$cfg" 2>&1)" && return 0
  printf '%s\n' "$out" | grep -q '没有任何可编译规则' || return 0
  if grep -qE '^[[:space:]]*(dip|domain|pname|qname|l4proto|dport|sip|ip)\(' "$cfg"; then
    warn "routing 段有规则字面但都不可编译，未自动修改；请手动检查 $cfg"
    return 1
  fi
  warn "配置的 routing 段没有可编译规则（引擎会拒启），补默认直连规则"
  tmp="$(mktemp)"
  awk '
    done != 1 && /^[[:space:]]*routing[[:space:]]*\{/ {
      print
      print "    dip(192.168.0.0/16) -> direct"
      print "    dip(10.0.0.0/8) -> direct"
      print "    dip(172.16.0.0/12) -> direct"
      print "    dip(169.254.0.0/16) -> direct"
      print "    dip(\047fe80::/10\047) -> direct"
      print "    dip(\047fc00::/7\047) -> direct"
      done = 1; next
    }
    { print }
  ' "$cfg" >"$tmp"
  cat "$tmp" >"$cfg"
  rm -f "$tmp"
  chmod 640 "$cfg"
  if out="$(sodama validate "$cfg" 2>&1)"; then
    ok "已补上默认直连规则，校验通过"
    return 0
  fi
  warn "补规则后仍然校验失败："
  printf '%s\n' "$out" >&2
  return 1
}

guide_config() {
  local cfg=/etc/sodama/config.dae
  [[ -f "$cfg" ]] || die "包内没有 $cfg，安装异常"

  # 旧模板遗留：routing 只有 fallback（不是规则）→ 引擎拒启，就地补默认规则
  ensure_routing_rules || warn "routing 段需你手动修复（见上）"

  if ! grep -q 'socks5://127.0.0.1:1080' "$cfg" && ((FORCE_CFG == 0)); then
    warn "检测到已有自定义配置（不含模板占位节点），本次跳过配置写入"
    warn "如需重新引导：sudo bash $0 --force-config"
    return 0
  fi

  hr
  echo "① 网卡（当前）"
  ip -br link | sed 's/^/     /'
  local d_wan d_lan
  d_wan="$(detect_wan)"
  d_lan="$(detect_lan)"

  [[ -n "$WAN" ]] || WAN="$(ask "WAN 网卡（默认路由所在，填错会断网）" "$d_wan")"
  [[ -n "$LAN" ]] || LAN="$(ask "LAN 网卡（网关模式填网桥；只代理本机填 none）" "$d_lan")"
  [[ -n "$WAN" ]] || die "WAN 网卡不能为空"
  ip link show dev "$WAN" >/dev/null 2>&1 || warn "WAN 接口 $WAN 当前不存在（热插拔可接受，请确认拼写）"
  if [[ "$LAN" != none ]]; then
    ip link show dev "$LAN" >/dev/null 2>&1 || warn "LAN 接口 $LAN 当前不存在"
  fi

  hr
  echo "② 出口节点"
  if [[ -z "$SUB" && -z "$NODE" ]]; then
    if ((ASSUME_YES)); then
      warn "--yes 模式未给 --sub/--node：只写网卡，节点保留模板占位"
    else
      cat <<'EOF' >&2
     1) 订阅链接（推荐；https:// 开头的订阅 URL，节点自动更新）
     2) 单个节点链接（vless://  ss://  trojan://  socks5:// …）
     3) 先跳过，我自己编辑 /etc/sodama/config.dae
EOF
      local choice
      choice="$(ask "选择" "1")"
      case "$choice" in
        1) SUB="$(ask "订阅 URL" "")" ;;
        2) NODE="$(ask "节点链接" "")" ;;
        *) warn "已跳过：没有出口节点时服务能起来但没有流量" ;;
      esac
    fi
  fi

  local block bak
  block="$(mktemp)"
  if [[ -n "$SUB" ]]; then
    valid_sub "$SUB" || die "订阅 URL 看起来不对（要 http(s):// 或本地文件路径）：$SUB"
    printf "subscription {\n    main: '%s'\n}\n" "$SUB" >"$block"
  elif [[ -n "$NODE" ]]; then
    valid_node "$NODE" || die "节点链接看起来不对（要 vless:// ss:// trojan:// 等）：$NODE"
    printf "node {\n    my: '%s'\n}\n" "$NODE" >"$block"
  fi

  bak="$cfg.bak-$(date +%Y%m%d-%H%M%S)"
  cp -a "$cfg" "$bak"

  cfg_set_global "$cfg" wan_interface "$WAN"
  cfg_set_global "$cfg" lan_interface "$LAN"
  if [[ -s "$block" ]]; then
    if [[ -n "$SUB" ]]; then
      cfg_delete_section "$cfg" node
      cfg_replace_section "$cfg" subscription "$block"
      # 订阅节点的名字来自订阅本身；模板里按内联节点名过滤会让组为空
      sed -i -E '/^[[:space:]]*filter:[[:space:]]*name\([[:space:]]*my[[:space:]]*\)[[:space:]]*$/d' "$cfg"
    else
      cfg_delete_section "$cfg" subscription
      cfg_replace_section "$cfg" node "$block"
    fi
  fi
  chmod 640 "$cfg"

  local out
  if ! out="$(sodama validate "$cfg" 2>&1)"; then
    warn "配置校验失败，已回滚到 $bak"
    printf '%s\n' "$out" >&2
    cat "$bak" >"$cfg"
    rm -f "$block"
    die "请手动编辑 $cfg 后重试"
  fi
  rm -f "$block"
  ok "配置已写入并校验通过（wan=$WAN lan=$LAN $([[ -n "$SUB" ]] && echo 订阅 || [[ -n "$NODE" ]] && echo 节点 || echo 仅网卡)）"
  ok "备份：$bak"
}

# ---------------------------------------------------------------- 面板
setup_panel() {
  local pcfg=/etc/sodama-panel/panel.conf
  local enable="$PANEL"
  if [[ -z "$enable" ]]; then
    if ask_yn "启用 Web 面板（浏览器里看状态/改配置）？" y; then enable=1; else enable=0; fi
  fi
  ((enable == 1)) || { ok "跳过 Web 面板"; return 0; }

  if [[ -z "$BIND" ]]; then
    if ((ASSUME_YES)); then
      BIND="127.0.0.1:8080"
    else
      cat <<'EOF' >&2
     面板监听范围：
       1) 局域网可访问 0.0.0.0:8080（方便；同网段都能打开）
       2) 仅本机   127.0.0.1:8080（安全；用 ssh -L 8080:127.0.0.1:8080 访问）
EOF
      local choice
      choice="$(ask "选择" "1")"
      if [[ "$choice" == 2 ]]; then BIND="127.0.0.1:8080"; else BIND="0.0.0.0:8080"; fi
    fi
  fi

  if [[ -z "$TOKEN" ]]; then
    if ((ASSUME_YES)); then
      TOKEN=""
    elif ask_yn "设置访问 token（不设 = 免认证，仅建议内网）？" n; then
      TOKEN="$(ask "token（回车即自动生成）" "$(head -c 16 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-16)")"
    else
      TOKEN=""
    fi
  fi

  [[ -f "$pcfg" ]] || { warn "找不到 $pcfg"; return 0; }
  cfg_set_kv "$pcfg" bind "$BIND"
  if [[ -n "$TOKEN" ]]; then cfg_set_kv "$pcfg" token "$TOKEN"; fi
  chmod 640 "$pcfg" 2>/dev/null || true
  PANEL_ON=1
  ok "面板配置：bind=$BIND token=$([[ -n "$TOKEN" ]] && echo 已设置 || echo 空)"
}

# ---------------------------------------------------------------- 主流程
do_install() {
  verify_pkg

  hr
  echo "③ 安装包"
  if systemctl is-active --quiet sodama 2>/dev/null; then
    warn "sodama 正在运行，先 stop（装完会重新启动）"
    systemctl stop sodama sodama-panel 2>/dev/null || true
  fi
  pacman -U --noconfirm "$PKG"
  ok "已安装 sodama-bin $(pacman -Q sodama-bin 2>/dev/null | awk '{print $2}')"

  guide_config
  setup_panel

  hr
  echo "④ 启动"
  local do_start="$START"
  if [[ -z "$do_start" ]]; then
    if ask_yn "启用开机自启并立即启动 sodama？" y; then do_start=1; else do_start=0; fi
  fi

  if ((do_start == 1)); then
    systemctl daemon-reload
    if systemctl enable --now sodama; then
      ok "sodama：$(systemctl is-active sodama)"
    else
      warn "启动失败，最近日志："
      journalctl -u sodama -b --no-pager -n 30 || true
    fi
    if ((PANEL_ON == 1)); then
      if systemctl enable --now sodama-panel; then
        ok "sodama-panel：$(systemctl is-active sodama-panel)"
      else
        warn "面板启动失败：journalctl -u sodama-panel -n 50"
      fi
    fi
  else
    warn "未启动。稍后：sudo systemctl enable --now sodama$([[ $PANEL_ON == 1 ]] && echo ' sodama-panel')"
  fi

  hr
  echo "⑤ 结果"
  if systemctl is-active --quiet sodama; then
    local eip
    eip="$(curl -fsS --max-time 8 https://api.ipify.org 2>/dev/null || true)"
    if [[ -n "$eip" ]]; then ok "当前出口 IP：$eip"; else warn "取出口 IP 失败（可能节点还没生效，看 journalctl）"; fi
  fi

  local lip panel_url
  lip="$(lan_ip)"
  panel_url=""
  if [[ "$PANEL_ON" == 1 ]]; then
    if [[ "$BIND" == 127.0.0.1* ]]; then
      panel_url="  面板（仅本机）：http://127.0.0.1:8080（远程：ssh -L 8080:127.0.0.1:8080 用户@主机）"
    else
      panel_url="  面板：http://${lip:-<本机IP>}:8080"
    fi
  fi
  cat <<EOF

—— 常用命令 ——
  systemctl status sodama                # 状态（Type=notify，READY 后可用）
  journalctl -u sodama -b -f             # 日志（同时写 /var/log/sodama.log）
  sudo systemctl reload sodama           # 改完配置热重载（不断流）
  sudo ${EDITOR:-vi} /etc/sodama/config.dae
  sudo sodama validate /etc/sodama/config.dae
  sudo /usr/lib/sodama/datapath status   # netns/veth/策略路由/sysctl
${panel_url}
  卸载（干净清理）：sudo bash $HERE/uninstall.sh

—— 出问题请回报 ——
  uname -r ; sodama --version
  journalctl -u sodama -b --no-pager | tail -100
  sudo sodama sysdump --socket /run/sodama/status.sock --out /tmp/sodama-dump.tar.gz
EOF
}

case "$MODE" in
  check)
    check_env
    verify_pkg
    ok "自检全部通过，可以安装：sudo bash $0"
    ;;
  install)
    [[ "$(id -u)" -eq 0 ]] || die "安装需要 root：sudo bash $0"
    if ((ASSUME_YES == 0)) && [[ ! -t 0 ]]; then
      die "当前不是交互终端；无人值守请用 --yes 并配合 --sub/--node"
    fi
    check_env
    do_install
    ;;
esac
