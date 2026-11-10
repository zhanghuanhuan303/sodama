#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

# sodama 真网关模式：在宿主 netns 用 eBPF 透明接管本机流量（浏览器零配置）。
#
#   sudo lab/gateway.sh up [--iface wlan0] [--node <文件|URL> | --subscribe <文件|URL>] [--group <名>] [--rules <文件> | --config <配置文件>] [--dns <上游URL>] [--geodata-dir <目录>] [--no-ipv6] [--dial-mode ip|domain] [--wait <秒>|--no-wait]
#   sudo lab/gateway.sh down          # 停止并恢复（幂等）
#   sudo lab/gateway.sh status        # 查看进程/钩子/日志
#   lab/gateway.sh test               # 连通性快检（可直接用当前用户跑）
#   sudo lab/gateway.sh up --dry-run  # 只打印将要执行的命令
#
# up 的启动自检（P19）：loader 起来后，等「节点组就绪 + 代理路径 204」才返回（默认最长
# 75s，--wait <秒> 或 --no-wait 可调）；超时自动 down 回滚直连，不会把机器晾在断网态。
#
# 原理（复用 lab.sh test-host-proxy 已验证的宿主流量路径，网卡不移动、不断网）：
#   - 物理网卡（默认路由网卡）留在宿主 netns，只挂 tc 钩子：
#       被判 proxy 的 TCP -> bpf_redirect 到 dae0 -> dae0peer ingress -> tproxy(daens)
#       被判 direct 的报文原样放行（内核正常收发）
#   - relay 在 host ns 拨号，出口 socket 打 SO_MARK=0x233，数据面跳过（不自环）；
#   - 回程由 dae0 ingress 按 redirect_track 还原 MAC 后 BPF_F_INGRESS 注回 WAN；
#   - DNS 默认被数据面自动送控制面 DNS 模块；本脚本配套规则用 direct(must)
#     把它压回系统解析路径（见 lab/rules.gateway.dae 的说明）。
#   - P14：默认 dial_mode=domain——relay 先嗅探 TLS SNI / HTTP Host，命中后把
#     域名（而不是被污染 DNS 解析出的 IP）交给节点远端解析；--dial-mode ip 可关。
#
# 安全与回滚：
#   - 不移动网卡、不碰 NetworkManager；loader 异常退出时 tc 钩子随进程自动拆除，
#     网络立即恢复直连。
#   - 恢复：sudo lab/gateway.sh down（杀进程、删 netns/veth、恢复 sysctl）。
#   - 节点 URL 只从 --node 参数或文件读取，绝不写进仓库；建议放 /tmp（权限 600）。
#
# 依赖：root；sodama loader 与 eBPF 对象已构建（lab/lab.sh build 或 lab/build-ebpf-rs.sh）。

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
LOADER="$ROOT/target/release/sodama"
OBJ="$ROOT/ebpf-rs/target/bpfel-unknown-none/release/sodama-ebpf"

# 与 lab.sh 区分开的专用名字（可同时存在互不干扰；pkill 依据 --daens 参数精确匹配）
DAE_NS=gwdae
DAE0=dae0gw
DAE0PEER=dae0gwpeer

# 日志默认持久化（/var/log，重启/清 /tmp 后仍可回溯）；不可写时回退 /tmp
LOG="${SODAMA_GW_LOG:-/var/log/sodama-gateway.log}"
PID_FILE=/tmp/sodama-gw.pid
STATUS_SOCK=/tmp/sodama-gw.sock
STATE_FILE=/tmp/sodama-gw.state
WATCHDOG_PID_FILE=/run/sodama-gateway.watchdog.pid
DEFAULT_NODE_FILE=/tmp/sodama-node.url

IFACE=""
RULES="$HERE/rules.gateway.dae"
RULES_GIVEN=0
DIAL_MODE_GIVEN=0
CONFIG=""
DNS=""
GEODATA_DIR=""
NODE=""
SUBSCRIBE=""
GROUP=""
DIAL_MODE="domain"
SNIFF_TIMEOUT_MS=100
NO_IPV6=0
DRY_RUN=0
# I7：节点看护（watchdog）开关与参数（env 可覆盖；up --no-watchdog 关闭）
WATCH=1
WATCH_INTERVAL="${GATEWAY_WATCH_INTERVAL:-15}"
WATCH_FAILS="${GATEWAY_WATCH_FAILS:-4}"
WATCH_TIMEOUT="${GATEWAY_WATCH_TIMEOUT:-6}"
# P19：up 启动自检的最长等待（秒）；0 = 不等（旧行为）
WAIT_SECS="${GATEWAY_WAIT_SECS:-75}"
# P33：配置文件热驱动（秒；0=关）——轮询 --config/--rules 及 include，变更即自动 reload
WATCH_CONFIG="${GATEWAY_WATCH_CONFIG:-0}"

die() { echo "错误：$*" >&2; exit 1; }
info() { echo "== $* =="; }

require_root() { [ "$(id -u)" -eq 0 ] || die "需要 root：sudo $0 $*"; }

run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '  +'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

usage() {
  cat <<'EOF'
用法：
  sudo lab/gateway.sh up [--iface wlan0] [--node <文件|URL> | --subscribe <文件|URL>] [--group <名>]
                        [--rules <文件> | --config <文件>] [--dns <上游URL>] [--geodata-dir <目录>]
                        [--no-ipv6] [--dial-mode ip|domain] [--wait <秒>|--no-wait] [--no-watchdog]
  sudo lab/gateway.sh down          # 停止并恢复（幂等；同时停掉看护）
  sudo lab/gateway.sh status        # 进程/钩子/看护/日志尾部
  lab/gateway.sh test                 # 连通性快检（可直接用当前用户跑）
  sudo lab/gateway.sh up --dry-run    # 只打印将要执行的命令

看护（watchdog，默认开启）：
  每 GATEWAY_WATCH_INTERVAL（默认 15s）经代理路径探测三目标：
  gstatic / cp.cloudflare / bing（wget，不经 pname 直连规则）+ LAN 对照。
  连续 GATEWAY_WATCH_FAILS（默认 4）次失败 → SIGHUP 热刷新订阅组，仍失败则
  自动 down 回退直连（fail-open）并写日志（避免“网挂了只能重启”）。

日志（持久）：默认 /var/log/sodama-gateway.log（SODAMA_GW_LOG 可改；不可写回退 /tmp）。
启动自检（P19）：loader 起来后等「节点组就绪 + 代理路径 204」（默认最长 75s，
--wait/--no-wait 可调）；超时自动 down 回滚直连，不会把机器瞬在断网态。

配置文件热驱动（P33）：GATEWAY_WATCH_CONFIG=<秒>（默认 0=关）。>0 时 loader
轮询 --config/--rules 及其 include 文件，变更即自动 reload（等价自动 SIGHUP）。

配置文件（P34）：未显式给 --rules/--config 时，默认按序查找：
  GATEWAY_USER_CONFIG > $XDG_CONFIG_HOME/sodama/config.dae > ~/.config/sodama/config.dae
  > /etc/sodama/config.dae（无 home 的软路由可用系统目录）
配置里的 subscription 段按声明顺序回退（pacman 镜像风格）；行为参数（拨号/嗅探/
健康/热驱动）建议全部写进 config（P35：config 为唯一事实来源），命令行仅保留进程级
参数（接口/netns/socket/日志）与调试覆盖（--dial-mode 等）。
EOF
}

detect_iface() {
  ip route show default 2>/dev/null |
    awk '{for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i + 1); exit}}'
}

detect_dns() {
  awk '/^nameserver/ {print $2; exit}' /etc/resolv.conf 2>/dev/null
}

save_sysctl() {
  local k="$1" v
  v="$(sysctl -n "$k" 2>/dev/null || echo NA)"
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "  + 记录 $k=$v"
    return 0
  fi
  printf '%s=%s\n' "$k" "$v" >>"$STATE_FILE"
}

restore_sysctls() {
  [ -f "$STATE_FILE" ] || return 0
  local line k v
  while IFS='=' read -r k v; do
    [ -n "$k" ] || continue
    [ "$v" != "NA" ] || continue
    run sysctl -qw "$k=$v" 2>/dev/null || true
  done <"$STATE_FILE"
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "  + 删除 $STATE_FILE"
  else
    rm -f "$STATE_FILE"
  fi
}

cleanup() {
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "  + （dry-run）停止旧实例、删 netns $DAE_NS / veth $DAE0"
    return 0
  fi
  # I7：先停看护，避免它在 down 过程中重新拉起或误报
  if [ -f "$WATCHDOG_PID_FILE" ]; then
    local wpid
    wpid="$(cat "$WATCHDOG_PID_FILE" 2>/dev/null || true)"
    if [ -n "$wpid" ] && kill -0 "$wpid" 2>/dev/null; then
      kill "$wpid" 2>/dev/null || true
    fi
    rm -f "$WATCHDOG_PID_FILE"
  fi
  local pid=""
  if [ -f "$PID_FILE" ]; then
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  fi
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    info "停止 sodama（pid $pid）"
    # I7：先 SIGCONT——假死（SIGSTOP）的进程先复位，TERM/KILL 才能生效
    kill -CONT "$pid" 2>/dev/null || true
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 30); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.1
    done
    kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$PID_FILE"
  # 兜底：pid 文件丢失时按该实例独有的 --daens 参数匹配
  pkill -f "daens $DAE_NS" 2>/dev/null || true
  sleep 0.2
  if ip netns list 2>/dev/null | grep -qw "$DAE_NS"; then
    run ip netns del "$DAE_NS" || true
  fi
  if ip link show dev "$DAE0" >/dev/null 2>&1; then
    run ip link del "$DAE0" || true
  fi
  rm -f "$STATUS_SOCK"
}

up() {
  [ "$DRY_RUN" -eq 1 ] || require_root up
  [ -x "$LOADER" ] || die "缺 loader：$LOADER（先 lab/lab.sh build）"
  [ -f "$OBJ" ] || die "缺 eBPF 对象：$OBJ（先 lab/build-ebpf-rs.sh）"
  # P34/P35：默认配置发现（未显式给 --config/--rules）——无 home 的软路由也能用：
  #   GATEWAY_USER_CONFIG > $XDG_CONFIG_HOME/sodama/config.dae > ~/.config/sodama/config.dae
  #   > /etc/sodama/config.dae
  local user_home="${HOME:-}"
  if [ -n "${SUDO_USER:-}" ]; then
    local h
    h="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
    [ -n "$h" ] && user_home="$h"
  fi
  local user_config=""
  local c
  for c in ${GATEWAY_USER_CONFIG:+"$GATEWAY_USER_CONFIG"} \
    ${XDG_CONFIG_HOME:+"$XDG_CONFIG_HOME/sodama/config.dae"} \
    ${user_home:+"$user_home/.config/sodama/config.dae"} \
    /etc/sodama/config.dae; do
    if [ -f "$c" ]; then user_config="$c"; break; fi
  done
  if [ -z "$CONFIG" ] && [ "$RULES_GIVEN" -eq 0 ] && [ -n "$user_config" ]; then
    CONFIG="$user_config"
  fi
  # 只用 config 时无需仓库 rules 文件
  [ -n "$CONFIG" ] || [ -f "$RULES" ] || die "缺规则文件：$RULES"
  case "$DIAL_MODE" in
  ip | domain | domain+ | domain++) ;;
  *) die "--dial-mode 取值非法：$DIAL_MODE（ip|domain|domain+）" ;;
  esac

  [ -n "$IFACE" ] || IFACE="$(detect_iface)"
  [ -n "$IFACE" ] || die "拿不到默认路由网卡，请用 --iface 指定"
  ip link show dev "$IFACE" >/dev/null 2>&1 || die "网卡 $IFACE 不存在"

  # P34：订阅来自 config subscription 段时（有 --config 无 --node/--subscribe），不再要求节点参数
  if [ -z "$NODE" ] && [ -z "$SUBSCRIBE" ] && [ -z "$CONFIG" ]; then NODE="$DEFAULT_NODE_FILE"; fi
  local node_url="" sub_url=""
  if [ -n "$SUBSCRIBE" ]; then
    if [ -f "$SUBSCRIBE" ]; then
      sub_url="$(tr -d ' \t\r\n' <"$SUBSCRIBE")"
    else
      sub_url="$SUBSCRIBE"
    fi
    [ -n "$sub_url" ] || die "订阅 URL 为空（--subscribe <文件|URL>）"
    case "$sub_url" in
    http*://* | file://*) ;;
    *) die "订阅 URL 无效（缺 scheme）：$SUBSCRIBE" ;;
    esac
  elif [ -n "$NODE" ]; then
    if [ -f "$NODE" ]; then
      node_url="$(tr -d ' \t\r\n' <"$NODE")"
    else
      node_url="$NODE"
    fi
    [ -n "$node_url" ] || die "缺少节点 URL（--node <文件|URL>，或写入 $DEFAULT_NODE_FILE）"
    case "$node_url" in
    *://*) ;;
    *) die "节点 URL 无效（缺少 scheme）：$NODE" ;;
    esac
  fi

  local dns_up dns_args rules_args geo_args
  dns_up="$(detect_dns)"
  [ -n "$dns_up" ] || dns_up="127.0.0.1"
  if [ -n "$CONFIG" ]; then
    [ -f "$CONFIG" ] || die "配置文件不存在：$CONFIG"
    chmod 640 "$CONFIG" 2>/dev/null || true
    rules_args=(--config "$CONFIG")
  else
    rules_args=(--rules "$RULES")
  fi
  geo_args=()
  [ -n "$GEODATA_DIR" ] && geo_args=(--geodata-dir "$GEODATA_DIR")
  # DNS 上游优先级：--dns 显式 > --config 内部（dns.upstream/dns.routing）> 系统检测
  if [ -n "$DNS" ]; then
    dns_args=(--dns-upstream "$DNS")
  elif [ -n "$CONFIG" ]; then
    dns_args=()
  else
    dns_args=(--dns-upstream "$dns_up:53")
  fi

  local dns_desc
  if [ -n "$DNS" ]; then
    dns_desc="$DNS"
  elif [ -n "$CONFIG" ]; then
    dns_desc="config"
  else
    dns_desc="$dns_up:53"
  fi
  info "真网关模式 iface=$IFACE dns=$dns_desc rules=${CONFIG:-$RULES} dial_mode=$DIAL_MODE${GROUP:+ group=$GROUP}"
  if [ -n "$sub_url" ]; then
    echo "   订阅：$(printf '%s' "$sub_url" | cut -d: -f1)://…（敏感信息不回显）"
  else
    echo "   节点：$(printf '%s' "$node_url" | cut -d: -f1)://…（敏感信息不回显）"
  fi

  cleanup
  restore_sysctls
  save_sysctl net.ipv4.conf.all.rp_filter
  save_sysctl net.ipv4.conf.default.rp_filter
  if [ "$NO_IPV6" -eq 1 ]; then
    save_sysctl "net.ipv6.conf.$IFACE.disable_ipv6"
  fi

  info "建立控制面对 netns=$DAE_NS veth=$DAE0/$DAE0PEER"
  run ip netns add "$DAE_NS"
  run ip link add "$DAE0" type veth peer name "$DAE0PEER"
  run ip link set "$DAE0PEER" netns "$DAE_NS"
  run ip link set "$DAE0" up
  run ip -n "$DAE_NS" link set lo up
  run ip -n "$DAE_NS" link set "$DAE0PEER" up
  # 对照 dae control/netns_utils.go（同 lab.sh）：169.254.0.11/32 生成正确 L3 头，
  # 默认路由走静态邻居 169.254.0.1（dae0 的 MAC），保证 tproxy 回包可发出。
  run ip -n "$DAE_NS" addr add 169.254.0.11/32 dev "$DAE0PEER"
  run ip -n "$DAE_NS" route add 169.254.0.1/32 dev "$DAE0PEER" scope link
  run ip -n "$DAE_NS" route add default via 169.254.0.1 dev "$DAE0PEER"
  local mac=""
  if [ "$DRY_RUN" -eq 1 ]; then
    mac="02:00:00:00:00:01"
  else
    mac="$(ip link show dev "$DAE0" | awk '/link\/ether/ {print $2; exit}')"
    [ -n "$mac" ] || die "拿不到 $DAE0 的 MAC"
  fi
  run ip -n "$DAE_NS" neigh add 169.254.0.1 lladdr "$mac" dev "$DAE0PEER" nud permanent
  run ip netns exec "$DAE_NS" sysctl -qw "net.ipv4.conf.$DAE0PEER.accept_local=1"
  run ip netns exec "$DAE_NS" sysctl -qw net.ipv4.ip_nonlocal_bind=1
  run ip -n "$DAE_NS" rule add fwmark 0x8000000/0x8000000 table 2023
  run ip -n "$DAE_NS" route add local default dev lo table 2023

  # P16：IPv6 数据面（对照 dae control/netns_utils.go setupIPv6Datapath）。
  # 静态 fe80 邻居不可省：动态 NDP 的 NA 回包会被 dae0peer_ingress
  # （非 TPROXY_MARK → SHOT）丢弃，网关邻居停在 INCOMPLETE，v6 回包发不出去。
  # 本机 IPv6 不可用时自动降级为仅 v4（loader 侧同样会降级）。
  if [ "$NO_IPV6" -eq 0 ] && run ip -6 addr add fe80::ecee:eeff:feee:eeee/128 dev "$DAE0" scope link nodad; then
    run sysctl -qw "net.ipv6.conf.$DAE0.forwarding=1"
    run ip -n "$DAE_NS" -6 route add default via fe80::ecee:eeff:feee:eeee dev "$DAE0PEER"
    run ip -n "$DAE_NS" -6 neigh add fe80::ecee:eeff:feee:eeee lladdr "$mac" dev "$DAE0PEER" nud permanent
    run ip -n "$DAE_NS" -6 rule add fwmark 0x8000000/0x8000000 table 2023
    run ip -n "$DAE_NS" -6 route add local default dev lo table 2023
  elif [ "$NO_IPV6" -eq 0 ]; then
    echo "   注意：$DAE0 的 IPv6 地址配置失败（本机 IPv6 可能已禁用），本次运行仅 IPv4 代理。"
  fi

  info "内核开关（rp_filter 放宽）"
  run sysctl -qw net.ipv4.conf.all.rp_filter=0
  run sysctl -qw net.ipv4.conf.default.rp_filter=0
  run sysctl -qw "net.ipv4.conf.$DAE0.accept_local=1"
  if [ "$NO_IPV6" -eq 1 ]; then
    run sysctl -qw "net.ipv6.conf.$IFACE.disable_ipv6=1"
    echo "   已临时关闭 $IFACE 的 IPv6（down 时恢复）"
  fi

  # P33：配置文件热驱动（可选；GATEWAY_WATCH_CONFIG=<秒> 启用）
  local watch_args=()
  [ "${WATCH_CONFIG:-0}" -gt 0 ] 2>/dev/null && watch_args=(--watch-config "$WATCH_CONFIG")
  info "启动 loader（log=$LOG${watch_args:+，watch-config=${WATCH_CONFIG}s}）"
  local dial_args=()
  if [ -n "$sub_url" ]; then
    dial_args=(--subscribe "$sub_url")
    [ -n "$GROUP" ] && dial_args+=(--group "$GROUP")
  elif [ -n "$node_url" ]; then
    dial_args=(--dialer "$node_url")
  fi
  # P35：配置是行为参数的唯一事实来源——用 config 时不再从命令行注入 dial/嗅探参数
  # （仅当用户显式给 --dial-mode 时作为调试覆盖）。rules 模式下保持旧默认。
  local behavior_args=()
  if [ -z "$CONFIG" ] || [ "$DIAL_MODE_GIVEN" -eq 1 ]; then
    behavior_args+=(--dial-mode "$DIAL_MODE")
  fi
  if [ -z "$CONFIG" ]; then
    behavior_args+=(--dial-timeout 15 --sniffing-timeout-ms "$SNIFF_TIMEOUT_MS")
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    echo -n "  + nohup $LOADER --ebpf $OBJ --lan none --wan $IFACE --dae0 $DAE0 --dae0peer $DAE0PEER --daens $DAE_NS"
    printf ' %q' "${rules_args[@]}" "${dial_args[@]}" "${geo_args[@]}" "${dns_args[@]}" "${watch_args[@]}" "${behavior_args[@]}" --status-socket "$STATUS_SOCK" --log-file "$LOG"
    echo " >>$LOG 2>&1 &"
    echo "（dry-run：未执行任何变更）"
    return 0
  fi
  prepare_log
  nohup "$LOADER" --ebpf "$OBJ" --lan none --wan "$IFACE" \
    --dae0 "$DAE0" --dae0peer "$DAE0PEER" --daens "$DAE_NS" \
    "${rules_args[@]}" "${dial_args[@]}" "${geo_args[@]}" "${dns_args[@]}" "${watch_args[@]}" "${behavior_args[@]}" \
    --status-socket "$STATUS_SOCK" --log-file "$LOG" >>"$LOG" 2>&1 &
  echo $! >"$PID_FILE"
  sleep 1.2
  if ! kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "--- 启动失败，日志尾部 ---" >&2
    tail -n 20 "$LOG" >&2 || true
    cleanup
    restore_sysctls
    die "loader 启动失败"
  fi
  echo "   loader pid=$(cat "$PID_FILE")"

  # P19：启动自检 + 失败自动回滚（组健康 + 轻量代理探针；见文件头注释）。
  if ! wait_ready; then
    info "启动自检未通过 → 自动回滚到直连"
    cleanup
    restore_sysctls
    echo "--- loader 日志尾部 ---" >&2
    tail -n 25 "$LOG" >&2 || true
    die "网关启动后自检失败（${WAIT_SECS}s），已自动回滚；本机网络保持直连"
  fi
  echo "   代理路径自检通过（节点组已就绪）"

  if [ "$NO_IPV6" -eq 1 ]; then
    echo "   已按 --no-ipv6 关闭 $IFACE 的 IPv6；数据面仅 IPv4。"
  elif ip -6 route show default 2>/dev/null | grep -q .; then
    echo "   IPv6 数据面已启用（v6 流量一并透明代理；如需关闭网卡 IPv6 可用 --no-ipv6）。"
  fi
  # I7：节点看护（fail-open）——探针必须经代理路径，故用 wget（curl/python3 在
  # rules.gateway.dae 里是 pname->direct 调试规则，会测到直连）。
  if [ "$WATCH" -eq 1 ]; then
    if command -v wget >/dev/null 2>&1; then
      SODAMA_GW_LOG="$LOG" \
        GATEWAY_WATCH_INTERVAL="$WATCH_INTERVAL" \
        GATEWAY_WATCH_FAILS="$WATCH_FAILS" \
        GATEWAY_WATCH_TIMEOUT="$WATCH_TIMEOUT" \
        setsid "$0" watchdog >>"$LOG" 2>&1 </dev/null &
      echo "   节点看护已启动（watchdog：${WATCH_INTERVAL}s/次，连续 ${WATCH_FAILS} 次失败自动回退直连）"
    else
      echo "   未找到 wget，跳过节点看护（无法探测代理路径）"
    fi
  fi
  echo "完成：浏览器直接访问即可，无需任何代理设置。"
  echo "   sudo $0 test    # 连通性快检   sudo $0 down    # 停止并恢复"
}

down() {
  require_root down
  info "停止并恢复"
  cleanup
  restore_sysctls
  info "当前默认路由"
  ip route show default || true
  ip -6 route show default 2>/dev/null || true
  echo "完成：本机网络已恢复为直连。"
}

# P19：启动自检：等节点组至少一个成员探测成功（last_ms 非空），且（有 wget 时）
# 轻量代理探针 204。返回 0 = 就绪；1 = 超时/loader 退出。
wait_ready() {
  local wait="${WAIT_SECS:-75}"
  if [ "$wait" -le 0 ]; then
    return 0
  fi
  local deadline=$((SECONDS + wait))
  local ready=0
  info "启动自检：等待节点组与代理路径就绪（最长 ${wait}s）"
  while [ "$SECONDS" -lt "$deadline" ]; do
    sleep 4
    local pid=""
    [ -f "$PID_FILE" ] && pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
      echo "   loader 已退出" >&2
      return 1
    fi
    # 1) 组健康：任一成员探测成功（last_ms 非空；未探测前的乐观 alive 不算）
    if ! "$LOADER" status --socket "$STATUS_SOCK" --json 2>/dev/null | python3 -c '
import json, sys
try:
    v = json.load(sys.stdin)
except Exception:
    sys.exit(1)
gs = v.get("groups") or ([v["group"]] if v.get("group") else [])
ok = any(
    n.get("last_ms") is not None
    for g in gs
    for n in (g.get("nodes") or [])
)
sys.exit(0 if ok else 1)
'; then
      continue
    fi
    # 2) 轻量代理路径探针（wget 走 fallback->proxy；缺 wget 时仅以组健康为准）
    if command -v wget >/dev/null 2>&1; then
      local code=""
      code="$(wget -S -O /dev/null --timeout=10 https://www.gstatic.com/generate_204 2>&1 \
        | awk '/HTTP\//{c=$2} END{print c}' || true)"
      if [ "$code" != "204" ]; then
        continue
      fi
    fi
    ready=1
    break
  done
  [ "$ready" = 1 ]
}

status() {
  info "进程"
  local pid=""
  [ -f "$PID_FILE" ] && pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [ -n "$pid" ] && [ -d "/proc/$pid" ]; then
    ps -o pid=,etime=,args= -p "$pid" 2>/dev/null \
      | sed -e 's#--dialer [^ ]*#--dialer <redacted>#' -e 's#--subscribe [^ ]*#--subscribe <redacted>#' \
      || true
  else
    echo "  sodama 未运行（或不是本脚本启动的实例）"
  fi
  info "netns / veth"
  ip netns list 2>/dev/null | grep -w "$DAE_NS" || echo "  无 $DAE_NS"
  ip -br link show "$DAE0" 2>/dev/null || echo "  无 $DAE0"
  info "tc 钩子（需要 root；bpftool）"
  local ifc="${IFACE:-$(detect_iface)}"
  if command -v bpftool >/dev/null 2>&1; then
    bpftool net show dev "$ifc" 2>/dev/null || echo "  （权限不足或网卡 $ifc 无钩子）"
  else
    echo "  未安装 bpftool"
  fi
  info "节点看护（watchdog）"
  local wpid=""
  [ -f "$WATCHDOG_PID_FILE" ] && wpid="$(cat "$WATCHDOG_PID_FILE" 2>/dev/null || true)"
  if [ -n "$wpid" ] && kill -0 "$wpid" 2>/dev/null; then
    echo "  运行中（pid $wpid，interval=${WATCH_INTERVAL}s fails=${WATCH_FAILS}）"
    grep -a "watchdog:" "$LOG" 2>/dev/null | tail -n 5 | sed 's/^/  /'
  else
    echo "  未运行（--no-watchdog 或已退出；日志：$LOG）"
  fi
  info "日志尾部（$LOG）"
  tail -n 8 "$LOG" 2>/dev/null || echo "  无日志"
}

test_conn() {
  local code exitip
  # 注意：规则里 pname(curl)->direct、pname(python3)->direct（调试用），所以用
  # curl 测到的是**直连**路径。快检希望覆盖**代理**路径，因此优先用 wget
  # （不在 pname 名单 → 走 fallback -> proxy）。
  if command -v wget >/dev/null 2>&1; then
    code="$(wget -S -O /dev/null --timeout=20 https://www.gstatic.com/generate_204 2>&1 \
      | awk '/HTTP\//{c=$2} END{print c}' || true)"
    # 出口 IP：多个回显端点回退（单一端点可能被部分节点/地区屏蔽，避免误报）
    for ep in https://api.ipify.org https://ifconfig.me/ip https://ipinfo.io/ip; do
      exitip="$(wget -qO- --timeout=20 "$ep" 2>/dev/null || true)"
      [ -n "$exitip" ] && break
    done
  else
    code="$(env -u http_proxy -u https_proxy -u all_proxy \
      curl -s -o /dev/null -w '%{http_code}' --max-time 20 \
      https://www.gstatic.com/generate_204 || true)"
    exitip="$(env -u http_proxy -u https_proxy -u all_proxy \
      curl -s --max-time 20 https://api.ipify.org || true)"
  fi
  echo "generate_204 -> ${code:-失败}（代理路径）"
  echo "出口 IP      -> ${exitip:-失败}"
  if getent hosts www.google.com >/dev/null 2>&1; then
    echo "DNS 解析     -> ok（www.google.com）"
  else
    echo "DNS 解析     -> 失败"
  fi
  if [ "$code" = "204" ]; then
    echo "PASS：本机流量已由 sodama 接管（eBPF 透明代理）"
  else
    echo "FAIL：请检查 sudo $0 status 与 $LOG"
    return 1
  fi
}

# ---------------------------------------------------------------- I7：节点看护

# 带时间戳追加到持久日志。
glog() { printf '[%s] %s\n' "$(date '+%F %T')" "$*" >>"$LOG"; }

# 准备持久日志（不可写回退 /tmp；>5MB 轮转一次）。
prepare_log() {
  local dir
  dir="$(dirname "$LOG")"
  if ! { mkdir -p "$dir" 2>/dev/null && : >>"$LOG" 2>/dev/null; }; then
    LOG=/tmp/sodama-gw.log
    : >>"$LOG" 2>/dev/null || true
  fi
  local sz
  sz="$(stat -c%s "$LOG" 2>/dev/null || echo 0)"
  if [ "$sz" -gt 5242880 ]; then
    mv -f "$LOG" "$LOG.1" 2>/dev/null || true
  fi
  glog "===== gateway up（看护=$WATCH interval=${WATCH_INTERVAL}s fails=$WATCH_FAILS timeout=${WATCH_TIMEOUT}s）====="
}

# 经代理路径的三目标探针（wget 不在 pname->direct 调试规则里）；≥2 成功视为通。
# 三目标并行 + --tries=1（失败不重试）：最坏耗时 ≈ WATCH_TIMEOUT，避免看护反应被重试拖慢。
canary_once() {
  local dir
  dir="$(mktemp -d /tmp/sodama-canary.XXXXXX 2>/dev/null || echo /tmp)"
  local urls=(http://cp.cloudflare.com/generate_204 https://www.gstatic.com/generate_204 https://www.bing.com/)
  local pids=() i=0
  for u in "${urls[@]}"; do
    (
      # KILL 硬超时：假死代理下 DNS/多地址尝试可能拖长，直接强杀
      timeout -s KILL $((WATCH_TIMEOUT + 1)) wget -q -O /dev/null --tries=1 \
        --timeout="$WATCH_TIMEOUT" "$u" 2>/dev/null && : >"$dir/ok.$i"
    ) &
    pids+=($!)
    i=$((i + 1))
  done
  # 硬 deadline 等待：无论子进程状态如何，函数在 WATCH_TIMEOUT+3 内返回
  local deadline=$((SECONDS + WATCH_TIMEOUT + 3)) p
  for p in "${pids[@]}"; do
    while kill -0 "$p" 2>/dev/null && [ "$SECONDS" -lt "$deadline" ]; do
      sleep 0.2
    done
    kill -9 "$p" 2>/dev/null || true
    wait "$p" 2>/dev/null || true
  done
  local ok=0
  for f in "$dir"/ok.*; do
    [ -e "$f" ] && ok=$((ok + 1))
  done
  rm -rf "$dir" 2>/dev/null || true
  [ "$ok" -ge 2 ]
}

# LAN 对照：默认网关可达（区分“本地上游不亮”与“代理层故障”）。
lan_ok() {
  local gw
  gw="$(ip route show default 2>/dev/null | awk '/default/{print $3; exit}')"
  [ -n "$gw" ] && ping -c1 -W1 "$gw" >/dev/null 2>&1
}

# 状态快照：每组 alive/成员、探测计数、延迟中位。
health_snapshot() {
  timeout 10 "$LOADER" status --socket "$STATUS_SOCK" --json 2>/dev/null | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    print("status 不可读")
    raise SystemExit
gs = d.get("groups") or ([d["group"]] if d.get("group") else [])
for g in gs:
    if not isinstance(g, dict):
        continue
    lats = sorted(
        n.get("ema_ms") or n.get("last_ms") or 0
        for n in (g.get("nodes") or []) if n.get("alive")
    )
    med = lats[len(lats) // 2] if lats else None
    print("组[{}] alive={}/{} probe={}/{} failover={} 延迟中位={}ms".format(
        g.get("name"), g.get("alive"), g.get("members"),
        g.get("probes_ok"), g.get("probes_fail"), g.get("failovers"), med))
' 2>/dev/null || echo "status 快照失败"
}

# 看护主循环：失败累计 → SIGHUP 刷订阅组 → 仍失败 → fail-open 回直连。
watchdog_loop() {
  echo $$ >"$WATCHDOG_PID_FILE"
  glog "watchdog: 启动（pid $$，interval=${WATCH_INTERVAL}s fails=${WATCH_FAILS} timeout=${WATCH_TIMEOUT}s）"
  local fails=0 snap_t=0
  while :; do
    sleep "$WATCH_INTERVAL"
    local pid=""
    [ -f "$PID_FILE" ] && pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
      glog "watchdog: loader 不在，退出"
      break
    fi
    if canary_once; then
      [ "$fails" -gt 0 ] && glog "watchdog: 连通恢复（此前连续失败 ${fails} 次）"
      fails=0
    else
      fails=$((fails + 1))
      if lan_ok; then
        glog "watchdog: 探针失败 ${fails}/${WATCH_FAILS}（LAN 正常，疑节点/订阅侧）"
      else
        glog "watchdog: 探针失败 ${fails}/${WATCH_FAILS}（LAN 也异常，优先排查本地上游）"
      fi
    fi
    snap_t=$((snap_t + WATCH_INTERVAL))
    if [ "$snap_t" -ge 300 ]; then
      snap_t=0
      glog "watchdog: 健康快照 | $(health_snapshot | tr '\n' ' ')"
    fi
    if [ "$fails" -ge "$WATCH_FAILS" ]; then
      glog "watchdog: 连续 ${fails} 次失败 → SIGHUP 热刷新订阅/组"
      kill -HUP "$pid" 2>/dev/null || true
      local i=0
      while [ "$i" -lt 2 ]; do
        sleep "$WATCH_INTERVAL"
        i=$((i + 1))
        glog "watchdog: 刷新后复检（第 ${i}/2 次）"
        canary_once && break
      done
      if canary_once; then
        glog "watchdog: 刷新后恢复正常"
        fails=0
        continue
      fi
      glog "watchdog: 刷新无效 → fail-open 切回直连（快照：$(health_snapshot | tr '\n' ' ')）"
      command -v notify-send >/dev/null 2>&1 \
        && notify-send -u critical "sodama 网关" "代理层连续失败，已自动切回直连（详见 $LOG）" || true
      "$0" down >>"$LOG" 2>&1 || true
      break
    fi
  done
  rm -f "$WATCHDOG_PID_FILE"
}

cmd="${1:-}"
[ $# -gt 0 ] && shift || true
while [ $# -gt 0 ]; do
  case "$1" in
  --iface) IFACE="$2"; shift 2 ;;
  --node) NODE="$2"; shift 2 ;;
  --subscribe) SUBSCRIBE="$2"; shift 2 ;;
  --group) GROUP="$2"; shift 2 ;;
  --rules) RULES="$2"; RULES_GIVEN=1; shift 2 ;;
  --config) CONFIG="$2"; shift 2 ;;
  --dns) DNS="$2"; shift 2 ;;
  --geodata-dir) GEODATA_DIR="$2"; shift 2 ;;
  --dial-mode) DIAL_MODE="$2"; DIAL_MODE_GIVEN=1; shift 2 ;;
  --wait) WAIT_SECS="$2"; shift 2 ;;
  --no-wait) WAIT_SECS=0; shift ;;
  --no-ipv6) NO_IPV6=1; shift ;;
  --no-watchdog) WATCH=0; shift ;;
  --dry-run) DRY_RUN=1; shift ;;
  -h | --help) usage; exit 0 ;;
  *) die "未知参数：$1" ;;
  esac
done

case "$cmd" in
up) up ;;
watchdog) require_root watchdog; watchdog_loop ;;
down) down ;;
status) status ;;
test) test_conn ;;
"" | help | -h | --help) usage ;;
*) die "未知子命令：$cmd" ;;
esac
