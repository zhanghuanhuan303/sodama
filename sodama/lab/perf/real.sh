#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

# G1：异机服务端 + 公网口径基准（真实订阅节点）。
#
# 拓扑：client ns — 网关（被测实现，透明代理）— 宿主默认路由 — 真实节点（异机）— 公网目标。
# 四实现共用同一节点、同一目标、同一时段；节点带宽是共同上限，因此对比口径为
# 「交付吞吐 + 被测进程 CPU/GB（客户端侧效率）」；并同时记录宿主内核侧 CPU（system+irq+softirq，
# 扣前置 1s 空闲基线），避免 sodama 的 eBPF 转发工作量在进程口径下被漏计。
# 原始行：impl mbps cpu_ms bytes seconds kern_ms base_ms（kern_ms=轮内内核侧；base_ms=前置 1s 空闲窗口）
#
# 用法：
#   sudo lab/perf/real.sh prepare          # 建拓扑并解析目标 IP
#   sudo lab/perf/real.sh bench sodama|dae|singbox|direct
#   sudo lab/perf/real.sh all
#   sudo lab/perf/real.sh down
#
# 节点来源（不入库）：REAL_NODE_FILE=/tmp/real-node.url（默认），文件内为一行 vless://…
#   REAL_NODE_URL=… 也可（不推荐：会出现在命令行）。
# prepare 会将节点域名固定到一个实测可连的后端 IP（/tmp/perf-real-node-pinned.url，
# 0600），三方实现共用同一后端，避免域名多 A 记录导致的不可比。
# 环境：
#   TARGET_HOST=proof.ovh.net TARGET_PATH='/files/10Mb.dat' TARGET_PORT=443
#   TARGET_SCHEME=https ROUNDS=3
#   DAE_BIN=/tmp/perf/usr/bin/dae  SINGBOX_BIN=sing-box
# 目标选择（2026-10-17 本机直连网络复测）：
#   - cachefly.cachefly.net/5mb.test：经节点可用但宿主直连不可达（direct 基线缺位），
#     且 CacheFly 对节点出口 IP 有配额限流（实测 403 Access Denied + x-cf-quota-*）。
#   - speed.cloudflare.com/__down：宿主直连可用，但经该 CF worker 节点 20s 超时。
#   - proof.ovh.net/files/10Mb.dat：宿主直连与经节点均稳定（17–32 Mbps），故选此。
# run_one 用 curl -f 并校验 HTTP 200（部分目标会用 403/204 + 小体积当“成功”）。
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$(dirname "$HERE")")"
LAB="$ROOT/lab/lab.sh"
LOADER="$ROOT/target/release/sodama"
OBJ="$ROOT/ebpf-rs/target/bpfel-unknown-none/release/sodama-ebpf"
DAE_BIN="${DAE_BIN:-/tmp/perf/usr/bin/dae}"
SINGBOX_BIN="${SINGBOX_BIN:-sing-box}"
CLIENT_NS=sodama_client
WAN_NS=sodama_wan
REAL_NODE_FILE="${REAL_NODE_FILE:-/tmp/real-node.url}"
TARGET_HOST="${TARGET_HOST:-proof.ovh.net}"
TARGET_SCHEME="${TARGET_SCHEME:-https}"
TARGET_PATH="${TARGET_PATH:-/files/10Mb.dat}"
TARGET_PORT="${TARGET_PORT:-443}"  # 目标协议/端口可配置；默认见文件头「目标选择」注释
ROUNDS="${ROUNDS:-3}"
# 期望下载字节数（空=不校验）。部分目标/CDN 会在传输中途断开而 curl 仍返回 200，
# 短体积轮次会把吞吐与 CPU/GB 同时拉低；设此值则短传输判失败并重试。
TARGET_EXPECT_BYTES="${TARGET_EXPECT_BYTES:-}"
# 单轮内部重试次数（网络/目标瞬时限流，如 CacheFly 配额 403）。
ROUND_ATTEMPTS="${ROUND_ATTEMPTS:-3}"
RESULTS="${RESULTS:-/tmp/perf-real.tsv}"
IMPL_PID_FILE=/tmp/perf-real-impl.pid
RULES_FILE=/tmp/perf-real-rules.dae
NODE_HOSTPORT_FILE=/tmp/perf-real-node-hostport
TARGET_IP_FILE=/tmp/perf-real-target-ip
NODE_IP_FILE=/tmp/perf-real-node-ip
NODE_URL_PINNED=/tmp/perf-real-node-pinned.url

die() { echo "!! $*" >&2; exit 1; }
require_root() { [ "$(id -u)" = 0 ] || die "需要 root：sudo $0 $*"; }
in_client() { ip netns exec "$CLIENT_NS" "$@"; }
# ns 精度进程级 CPU：汇总所有线程的 schedstat（jiffies 10ms 粒度太粗，
# 单轮只有几十 ms CPU，会把差异淹没在量化误差里）。单位 ms。
proc_cpu_ms() {
  awk '{s+=$1} END {printf "%.3f", s/1e6}' "/proc/$1/task/"*/schedstat 2>/dev/null \
    || echo 0
}
# 宿主内核侧 CPU（system+irq+softirq，排除 idle/iowait/user），单位 ms。
# 仅进程级 CPU 对 sodama 不公平：其转发在 eBPF 里完成，不计入用户态进程；
# 该口径为「交付这批字节的客户端侧内核/数据面成本」，四实现一致可比。
# 排除 user 的理由：宿主后台（编辑器等）在 user，会淹没信号。
sys_cpu_ms() {
  awk '/^cpu /{printf "%.0f", ($4+$7+$8)*10}' /proc/stat
}

node_url() {
  if [ -n "${REAL_NODE_URL:-}" ]; then
    printf '%s' "$REAL_NODE_URL"
  elif [ -f "$REAL_NODE_FILE" ]; then
    head -1 "$REAL_NODE_FILE"
  else
    die "缺节点：设 REAL_NODE_FILE（默认 $REAL_NODE_FILE）或 REAL_NODE_URL"
  fi
}

prepare() {
  require_root
  [ -n "$(node_url)" ] || die "节点为空"
  [ -x "$LOADER" ] && [ -f "$OBJ" ] || die "先构建 sodama（lab.sh build + cargo build --release）"
  "$LAB" down >/dev/null 2>&1 || true
  TOPO_ONLY=1 "$LAB" up
  local ip
  ip="$(getent ahostsv4 "$TARGET_HOST" | awk 'NR==1{print $1}')"
  [ -n "$ip" ] || die "解析 $TARGET_HOST 失败"
  echo "$ip" >"$TARGET_IP_FILE"
  pin_node_ip
  printf 'dip(%s/32) -> proxy\nfallback -> direct\n' "$ip" >"$RULES_FILE"
  chmod 640 "$RULES_FILE"
  # 目标连通性（直连，不过代理）：确认宿主机可达该 IP。
  timeout 5 bash -c ": >/dev/tcp/$ip/$TARGET_PORT" 2>/dev/null \
    || echo "  警告：宿主直连 $ip:$TARGET_PORT 不通（节点侧仍可能可达，继续）"
  local src="file:$REAL_NODE_FILE"
  [ -n "${REAL_NODE_URL:-}" ] && src="env:REAL_NODE_URL"
  local nip
  nip="$(cat "$NODE_IP_FILE" 2>/dev/null || echo '?')"
  echo "== 就绪：目标 $TARGET_HOST -> $ip，节点来自 $src（固定后端 $nip） =="
}

# 订阅域名后常有多个后端 IP，各实现各自解析会跑在不同后端上（吞吐不可比）。
# 这里解析一次、逐个 TCP 探测，固定到第一个可连 IP，并生成 host 已替换的 URL，
# 供 sodama/dae/sing-box 三方共用；凭据只经 600 权限文件传递，不打印。
pin_node_ip() {
  local hp host port ips node_ip
  hp="$(printf '%s' "$(node_url)" | python3 -c 'import sys,urllib.parse;u=urllib.parse.urlsplit(sys.stdin.read().strip());print(u.hostname, u.port)')" \
    || die "解析节点 URL 失败"
  host="${hp% *}"; port="${hp#* }"
  ips="$(getent ahostsv4 "$host" | awk '{print $1}' | sort -u)"
  [ -n "$ips" ] || die "解析节点域名 $host 失败"
  node_ip=""
  local cand
  for cand in $ips; do
    if timeout 4 bash -c ": >/dev/tcp/$cand/$port" 2>/dev/null; then node_ip="$cand"; break; fi
  done
  if [ -z "$node_ip" ]; then
    node_ip="$(echo "$ips" | awk 'NR==1{print $1}')"
    echo "  警告：节点后端均未通过 TCP 探测，仍固定 $node_ip"
  fi
  echo "$node_ip" >"$NODE_IP_FILE"
  printf '%s' "$(node_url)" | python3 -c '
import sys, urllib.parse
ip, out = sys.argv[1], sys.argv[2]
u = urllib.parse.urlsplit(sys.stdin.read().strip())
userinfo = (u.username or "") + "@" if u.username else ""
port = f":{u.port}" if u.port else ""
netloc = f"{userinfo}{ip}{port}"
open(out, "w").write(urllib.parse.urlunsplit(u._replace(netloc=netloc)))
' "$node_ip" "$NODE_URL_PINNED"
  chmod 600 "$NODE_IP_FILE" "$NODE_URL_PINNED"
}

# 代理规则由 sodama 每次启动时重新生成到 $RULES_FILE（prepare 也写一份，
# 但 direct 轮次不会再覆盖它——历史上曾因共用文件被 `-> direct` 覆盖导致
# sodama 启动后全部放行、透明代理失效）。
write_rules_proxy() {
  local ip="$1"
  printf 'dip(%s/32) -> proxy\nfallback -> direct\n' "$ip" >"$RULES_FILE"
  chmod 640 "$RULES_FILE"
}

nft_add() {
  local port="$1"
  nft delete table inet perfproxy 2>/dev/null || true
  nft add table inet perfproxy
  nft "add chain inet perfproxy prerouting { type filter hook prerouting priority mangle; }"
  nft add rule inet perfproxy prerouting iifname landae ip protocol tcp meta mark set 1 tproxy ip to ":$port"
  ip rule add fwmark 1 lookup 100 2>/dev/null || true
  ip route add local 0.0.0.0/0 dev lo table 100 2>/dev/null || true
}

nft_del() {
  nft delete table inet perfproxy 2>/dev/null || true
  ip rule del fwmark 1 lookup 100 2>/dev/null || true
  ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null || true
}

forward_allow() {
  command -v iptables >/dev/null 2>&1 || return 0
  iptables -C FORWARD -i "$1" -o "$2" -j ACCEPT 2>/dev/null ||
    iptables -I FORWARD 1 -i "$1" -o "$2" -j ACCEPT 2>/dev/null || true
  iptables -C FORWARD -i "$2" -o "$1" -j ACCEPT 2>/dev/null ||
    iptables -I FORWARD 1 -i "$2" -o "$1" -j ACCEPT 2>/dev/null || true
}

# direct 基线：TOPO_ONLY 拓扑下没有数据面，需要内核 NAT + FORWARD 放行才通。
nat_on() {
  local wif
  wif="$(ip route get "$(cat "$TARGET_IP_FILE")" | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
  [ -n "$wif" ] || { echo "  警告：拿不到宿主出口网卡，direct 可能不通"; return 0; }
  nft delete table ip perfnat 2>/dev/null || true
  nft add table ip perfnat
  nft "add chain ip perfnat postrouting { type nat hook postrouting priority srcnat; }"
  nft add rule ip perfnat postrouting ip saddr 10.0.0.0/24 oifname "$wif" masquerade
  forward_allow landae "$wif"
  echo "  direct NAT：10.0.0.0/24 -> $wif masquerade"
}

nat_off() {
  nft delete table ip perfnat 2>/dev/null || true
}

impl_env_cleanup() {
  nft_del
  nat_off
  ip netns del dae 2>/dev/null || true
  ip netns del daed 2>/dev/null || true
  pkill -f "sing-box run -c /tmp/perf-real" 2>/dev/null || true
}

# 官方 dae 会自建控制面对并可能在退出时清掉 dae0；sodama 需要拓扑里的 dae0。
ensure_dae0() {
  if ! ip link show dae0 >/dev/null 2>&1; then
    echo "  注：dae0 缺失（官方 dae 重建过数据面），重建拓扑…"
    TOPO_ONLY=1 "$LAB" up >/dev/null 2>&1 || { echo "!! 拓扑重建失败"; return 1; }
  fi
}

gen_singbox_cfg() {
  # 从节点 URL 生成 sing-box 配置（vless + reality/utls 或 ws+tls；URL 只经文件传递）。
  # 嗅探开启（sniff timeout 800ms）；但 sing-box ≥1.11 的 sniff action 无法回写
  # 拨号目标（见路由规则注释），故对「仅收 domain」的 CF worker 节点用
  # route action 的 override_address 静态指定域名。
  # 先删旧文件：/tmp 是 sticky + world-writable，宿主 fs.protected_regular=2 会
  # 拒绝 root 以 O_CREAT 打开他人拥有的常规文件（历史踩坑：PermissionError EACCES）。
  rm -f /tmp/perf-real-singbox.json
  python3 - "$1" /tmp/perf-real-singbox.json "$TARGET_IP_FILE" "$TARGET_HOST" <<'PY'
import json, sys
from urllib.parse import urlparse, parse_qs
url, out, ipf, target_host = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
u = urlparse(url)
q = parse_qs(u.query)
target_ip = open(ipf).read().strip()
tls = {
    "enabled": True,
    "server_name": (q.get("sni") or q.get("servername") or [u.hostname])[0],
    "utls": {"enabled": True, "fingerprint": (q.get("fp") or ["chrome"])[0]},
}
if (q.get("security") or [""])[0] == "reality":
    tls["reality"] = {
        "enabled": True,
        "public_key": q["pbk"][0],
        "short_id": (q.get("sid") or [""])[0],
    }
proxy = {
    "type": "vless", "tag": "proxy",
    "server": u.hostname, "server_port": u.port,
    "uuid": u.username,
    "flow": (q.get("flow") or [""])[0],
    "tls": tls,
}
# ws 传输（CF 边缘订阅节点的常见形态）：type=ws + host/path 透传。
if (q.get("type") or ["tcp"])[0] == "ws":
    proxy["transport"] = {
        "type": "ws",
        "path": (q.get("path") or ["/"])[0],
        "headers": {"Host": (q.get("host") or [u.hostname])[0]},
    }
cfg = {
    "log": {"level": __import__("os").environ.get("SINGBOX_LOG", "error")},
    "inbounds": [{
        "type": "tproxy", "tag": "in", "listen": "0.0.0.0", "listen_port": 7895,
    }],
    "outbounds": [proxy, {"type": "direct", "tag": "direct"}],
    "route": {
        # sing-box ≥1.11：嗅探改用 route rule action（legacy inbound 字段已移除）；
        # 高延迟链路（实测 RTT ~185ms）拉长嗅探等待。
        # 注意：1.11 起 sniff action 不再提供 destination override
        # （option/inbound.go 的 sniff_override_destination 是 schema:omit 的遗留
        # no-op；RuleActionSniff.OverrideDestination 亦从不赋值），故对
        # 「仅接受 domain 目标」的 CF 边缘节点（worker）只能用 route action 的
        # override_address 静态指定域名（badoption.Addr 支持域名 → 出站按域名拨号）。
        # 保留 sniff 规则：与 sodama/dae 的嗅探工作量对齐，避免少算 CPU。
        "rules": [
            {"action": "sniff", "timeout": "800ms"},
            {
                "ip_cidr": [target_ip + "/32"],
                "action": "route",
                "outbound": "proxy",
                "override_address": target_host,
            },
        ],
        "final": "direct",
    },
}
with open(out, "w") as f:
    json.dump(cfg, f)
PY
  chmod 600 /tmp/perf-real-singbox.json
}

gen_dae_cfg() {
  rm -f /tmp/perf-real-dae.dae
  python3 - "$1" /tmp/perf-real-dae.dae "$TARGET_IP_FILE" <<'PY'
import sys
url, out, ipf = sys.argv[1], sys.argv[2], sys.argv[3]
target_ip = open(ipf).read().strip()
cfg = f"""global {{
    wan_interface: wan
    lan_interface: landae
    tproxy_port: 12345
    log_level: {__import__("os").environ.get("DAE_LOG", "warn")}
    auto_config_kernel_parameter: true
    # CF 边缘订阅节点（worker 仅收域名目标）：domain+ = 对代理流始终域名拨号；
    # 高延迟链路拉长嗅探等待。（domain 严格档对未知域名首连会按 IP 拨号，
    # 这类 worker 会直接关闭——与 dae 的 ChooseDialTarget 同构，故用 domain+。）
    dial_mode: domain+
    sniffing_timeout: 500ms
    tcp_check_url: 'http://www.gstatic.com/generate_204'
    check_interval: 10s
}}
node {{
    real: '{url}'
}}
group {{
    proxy {{
        policy: min_moving_avg
        filter: name(real)
    }}
}}
routing {{
    dip({target_ip}/32) -> proxy
    fallback: direct
}}
"""
open(out, "w").write(cfg)
PY
  chmod 640 /tmp/perf-real-dae.dae
}

start_impl() {
  local impl="$1"
  local pid=""
  case "$impl" in
  sodama)
    ensure_dae0 || return 1
    write_rules_proxy "$(cat "$TARGET_IP_FILE")"
    local dialer
    dialer="$(cat "$NODE_URL_PINNED" 2>/dev/null || node_url)"
    "$LOADER" --ebpf "$OBJ" --lan landae --wan wan \
      --dae0 dae0 --dae0peer dae0peer --daens sodamans \
      --rules "$RULES_FILE" --dialer "$dialer" \
      --dial-mode "${REAL_DIAL_MODE:-domain+}" --sniffing-timeout-ms "${REAL_SNIFF_MS:-500}" \
      --status-socket /tmp/sodama-status.sock >/tmp/perf-real-sodama.log 2>&1 &
    pid=$!
    ;;
  dae)
    [ -x "$DAE_BIN" ] || { echo "!! 缺 dae（DAE_BIN=$DAE_BIN）"; return 1; }
    gen_dae_cfg "$(cat "$NODE_URL_PINNED" 2>/dev/null || node_url)"
    "$DAE_BIN" run --config /tmp/perf-real-dae.dae --disable-pidfile >/tmp/perf-real-dae.log 2>&1 &
    pid=$!
    ;;
  singbox)
    command -v "$SINGBOX_BIN" >/dev/null || { echo "!! 缺 sing-box"; return 1; }
    gen_singbox_cfg "$(cat "$NODE_URL_PINNED" 2>/dev/null || node_url)"
    nft_add 7895
    "$SINGBOX_BIN" run -c /tmp/perf-real-singbox.json >/tmp/perf-real-singbox.log 2>&1 &
    pid=$!
    ;;
  direct)
    nat_on
    echo "== direct：直连基线（无实现） =="
    rm -f "$IMPL_PID_FILE"
    return 0
    ;;
  v2ray)
    echo "skip: v2ray-core 不支持 VLESS-REALITY（需 Xray），本节点无法四方向对比"
    return 1
    ;;
  *) die "未知实现：$impl" ;;
  esac
  echo "$pid" >"$IMPL_PID_FILE"
  sleep 2.5
  if ! kill -0 "$pid" 2>/dev/null; then
    tail -20 "/tmp/perf-real-$impl.log" 2>/dev/null
    echo "!! $impl 启动失败"
    rm -f "$IMPL_PID_FILE"
    return 1
  fi
  echo "== $impl 运行中（pid $pid） =="
}

stop_impl() {
  if [ -f "$IMPL_PID_FILE" ]; then
    local pid
    pid="$(cat "$IMPL_PID_FILE")"
    kill "$pid" 2>/dev/null || true
    sleep 1.0
    kill -9 "$pid" 2>/dev/null || true
    rm -f "$IMPL_PID_FILE"
  fi
  impl_env_cleanup
}

# 一轮下载：输出 TSV 行 impl mbps cpu_ms bytes seconds sys_ms
# 传输失败/短体积时内部重试（最多 $ROUND_ATTEMPTS 次），避免瞬时限流污染样本。
run_one() {
  local impl="$1"
  local attempt
  for attempt in $(seq 1 "$ROUND_ATTEMPTS"); do
    _run_one_once "$impl" && return 0
    [ "$attempt" -lt "$ROUND_ATTEMPTS" ] && { echo "  .. [$impl] 第 $attempt 次失败，2s 后重试"; sleep 2; }
  done
  return 1
}

_run_one_once() {
  local impl="$1"
  local ip; ip="$(cat "$TARGET_IP_FILE")"
  local pid=""
  [ -f "$IMPL_PID_FILE" ] && pid="$(cat "$IMPL_PID_FILE")"
  local cpu0="0" cpu1="0" sys0 sys1 sysb0 sysb1
  # 前置 1s 空闲窗口：测宿主内核侧背景速率（round 净增 = round 内 kernelside - 背景×时长）
  sysb0="$(sys_cpu_ms)"; sleep 1.0; sysb1="$(sys_cpu_ms)"
  [ -n "$pid" ] && cpu0="$(proc_cpu_ms "$pid")"
  sys0="$(sys_cpu_ms)"
  local out
  out="$(in_client timeout 300 curl -fsS -o /dev/null \
    --resolve "$TARGET_HOST:$TARGET_PORT:$ip" \
    -w '%{http_code} %{speed_download} %{time_total} %{size_download}' \
    "${TARGET_SCHEME}://$TARGET_HOST:$TARGET_PORT$TARGET_PATH" 2>/tmp/perf-real-curl.err || true)"
  [ -n "$pid" ] && cpu1="$(proc_cpu_ms "$pid")"
  sys1="$(sys_cpu_ms)"
  local code spd secs size mbps
  code="$(awk '{print $1}' <<<"$out")"
  spd="$(awk '{print $2}' <<<"$out")"
  secs="$(awk '{print $3}' <<<"$out")"
  size="$(awk '{print $4}' <<<"$out")"
  if [ "$code" != "200" ] || [ -z "$spd" ] || [ "${spd%.*}" -le 0 ] 2>/dev/null; then
    echo "!! [$impl] 下载失败：code=${code:-?} out=[$out] $(tail -c 120 /tmp/perf-real-curl.err 2>/dev/null | tr '\n' ' ')"
    return 1
  fi
  if [ -n "$TARGET_EXPECT_BYTES" ] && [ "${size%.*}" -lt "$TARGET_EXPECT_BYTES" ] 2>/dev/null; then
    echo "!! [$impl] 短传输：size=${size} < 期望 ${TARGET_EXPECT_BYTES}（判失败）"
    return 1
  fi
  mbps="$(awk -v b="$spd" 'BEGIN{printf "%.1f", b*8/1e6}')"
  local cpu sysd base
  cpu="$(awk -v a="$cpu0" -v b="$cpu1" 'BEGIN{printf "%.1f", b-a}')"
  sysd="$(awk -v a="$sys0" -v b="$sys1" 'BEGIN{printf "%.1f", b-a}')"
  # 背景速率（内核侧 ms/s，1s 空闲窗口实测）
  base="$(awk -v a="$sysb0" -v b="$sysb1" 'BEGIN{printf "%.1f", b-a}')"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$impl" "$mbps" "$cpu" "$size" "$secs" "$sysd" "$base" | tee -a "$RESULTS"
}

bench_impl() {
  local impl="$1"
  if ! start_impl "$impl"; then return 1; fi
  local i
  for i in $(seq 1 "$ROUNDS"); do
    run_one "$impl" || { stop_impl; return 1; }
  done
  stop_impl
  return 0
}

medians() {
  python3 - "$RESULTS" <<'PY'
import sys, statistics as st, collections
rows = collections.defaultdict(list)
for line in open(sys.argv[1]):
    p = line.rstrip("\n").split("\t")
    if len(p) != 7:
        continue
    rows[p[0]].append(p)
print(f"{'impl':10} {'Mbps(med)':>10} {'CPU_ms(med)':>12} {'CPU_ms/GB(med)':>15} {'CPU_ms/GB(total)':>17} {'kern_net/GB(total)':>18} {'size_MB':>8}")
for impl, rs in rows.items():
    mb = st.median(float(r[1]) for r in rs)
    cpu = st.median(float(r[2]) for r in rs)
    size = st.median(float(r[3]) for r in rs)
    gb = size / 1e9
    per_gb = cpu / gb if gb > 0 else 0
    tot_cpu = sum(float(r[2]) for r in rs)
    tot_size = sum(float(r[3]) for r in rs)
    tot_gb = tot_cpu / (tot_size / 1e9) if tot_size > 0 else 0
    # 内核侧净增量用「聚合口径」（比值 of 和，抑噪）：
    # net_rate(ms/s) = Σkern/Σsecs - mean(base)；net_ms/GB = net_rate×Σsecs/ΣGB
    sum_secs = sum(float(r[4]) for r in rs)
    net_rate = sum(float(r[5]) for r in rs) / sum_secs - sum(float(r[6]) for r in rs) / len(rs)
    net_gb = net_rate * sum_secs / (tot_size / 1e9) if tot_size > 0 else 0
    print(f"{impl:10} {mb:10.1f} {cpu:12.1f} {per_gb:15.1f} {tot_gb:17.1f} {net_gb:18.1f} {size/1e6:8.1f}")
PY
}

all() {
  require_root
  : >"$RESULTS"
  bench_impl sodama || echo "!! sodama 跳过"
  bench_impl dae || echo "!! dae 跳过"
  bench_impl singbox || echo "!! singbox 跳过"
  bench_impl direct || echo "!! direct 跳过"
  echo "== 汇总（中位数）=="
  medians
}

down() {
  stop_impl
  "$LAB" down >/dev/null 2>&1 || true
  rm -f /tmp/perf-real-*.log /tmp/perf-real-singbox.json /tmp/perf-real-dae.dae \
    "$NODE_URL_PINNED" 2>/dev/null || true
  echo "== 已清理 =="
}

case "${1:-}" in
prepare) prepare ;;
bench)
  require_root
  shift
  : >"$RESULTS"
  bench_impl "${1:?impl}" || true
  medians
  ;;
all) all ;;
down) down ;;
v2ray) echo "skip: v2ray-core 不支持 VLESS-REALITY（需 Xray）" ;;
*)
  sed -n '2,22p' "$0"
  exit 2
  ;;
esac
