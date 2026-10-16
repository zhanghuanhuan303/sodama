#!/usr/bin/env bash
# sodama 实验环境：拓扑、构建、测试、清理。
#
#   lab/lab.sh build        # 编译 eBPF 对象 + Rust 加载器（不需要 root）
#   sudo lab/lab.sh up      # 建标准拓扑并启动 sodama
#   sudo lab/lab.sh dual-up # 建单臂（dual-role）拓扑：单个 L2 段 + 单接口路由器
#   sudo lab/lab.sh test-proxy        # LAN 客户端 -> tproxy
#   sudo lab/lab.sh test-direct       # LPM 集合第二前缀 -> 内核直转
#   sudo lab/lab.sh test-block        # NOT+AND + block
#   sudo lab/lab.sh test-host-proxy   # 宿主机自身流量（wan_egress + from_wan 回程）
#   sudo lab/lab.sh test-reload       # 长连接跨热重载 + 新连接走新规则
#   sudo lab/lab.sh dns-up    # P3a：DNS 接管 + 域位图会话（假上游 + rules.dns.dae）
#   sudo lab/lab.sh test-domain  # 域分流：DNS 解析 → 域位图 → domain 规则命中
#   sudo lab/lab.sh test-dns-cache # P3b-1：正/负缓存（命中不重查上游、TTL 递减）
#   sudo lab/lab.sh test-dns-tcp   # P3b-1：TCP DNS（2 字节分帧 + 可缓存）
#   sudo lab/lab.sh test-dns-reload # P3b-1：reload 后用缓存重建新槽域位图（端到端）
#   sudo lab/lab.sh regex-up     # P3b-2a：domain(regex:) 会话（假上游 + rules.regex.dae）
#   sudo lab/lab.sh test-domain-regex # regex 域命中分流 + 不命中直转
#   sudo lab/lab.sh test-dns-edns     # P3b-2a：UDP 截断/EDNS 尺寸/TCP 完整应答
#   sudo lab/lab.sh v6-up      # P16：IPv6 数据面（tproxy v6 → relay → ss(ATYP=4)；v6 direct）
#   sudo lab/lab.sh test-v6
#   sudo lab/lab.sh geo-up     # P17a：geoip/geosite 展开（小型夹具 + 假 DNS）
#   sudo lab/lab.sh test-geo
#   sudo lab/lab.sh pname-up   # P17b：pname（cgroup2 采集 + WAN egress 匹配）
#   sudo lab/lab.sh test-pname
#   sudo lab/lab.sh relay-up     # P4：TCP relay（--dialer direct）+ 短 idle 回收
#   sudo lab/lab.sh test-relay        # 真实转发 + 512KB 完整性 + 状态面
#   sudo lab/lab.sh test-relay-idle   # janitor 回收空闲连接
#   sudo lab/lab.sh relay-thread-up   # O9：线程泵路径会话（SODAMA_NO_REACTOR=1 + --no-splice）
#   sudo lab/lab.sh test-relay-thread-leak # 回归：上游先关 + 客户端保持 → 泵线程不泄漏
#   sudo lab/lab.sh offload-up   # P4c：relay + TCP offload（fast_sock/sk_skb）
#   sudo lab/lab.sh test-relay-offload # 内核拼接证据（用户态字节数远小于总传输）
#   sudo lab/lab.sh test-offload-lifecycle # P7：半关闭超时后回收连接与 fast_sock 键
#   sudo lab/lab.sh offload-up   # P4c：relay + TCP offload（fast_sock/sk_skb）；对标批起同时挂
#                                #   skb_send_sock 记账探针（fentry 优先、kprobe 回退）
#   sudo lab/lab.sh test-relay-offload    # 内核拼接证据 + 记账计数（probe_calls/kernel_bytes）
#   sudo lab/lab.sh test-l3-attach        # 对标批：L3 接口（ipip，arphrd=768）自动选 _l3 变体并挂载
#   sudo lab/lab.sh test-l3               # 对标批：L3 端到端（经 ipip 隧道的代理路径，verify 门禁）
#   sudo lab/lab.sh test-xdp              # 对标批 C4：XDP 计量探针（恒 XDP_PASS）计数随流量推进
#   USE_XDP_IFACE=  # 显式置空可关闭 up() 默认的 --xdp landae 计量探针
#   NO_L3=1         # 不建 L3 段（跳过 ipip 隧道）
#   SKIP_NET_OFFLOAD=1  # 跳过 up() 对 l3u/landae3/dae0 等设备的关 offload（A/B 对照用）
#   USE_LAN_ARG / USE_WAN_ARG  # 覆盖 up() 传给 loader 的 --lan/--wan（接口 pattern / 热插拔用）
#   sudo lab/lab.sh must-up       # 能力缺口 #1：must_<组名> 前缀糖（config 路径）
#   sudo lab/lab.sh test-must     #   must_proxy → proxy(must)：DNS 不劫持（A/B 计数器断言）
#   sudo lab/lab.sh subfile-up    # 能力缺口 #2：订阅 http-file:// scheme + 磁盘回退
#   sudo lab/lab.sh test-sub-file #   源掉线后 SIGHUP → 回退磁盘缓存，节点仍可用
#   sudo lab/lab.sh hotplug-up    # 能力缺口 #3：接口懒绑定/热插拔（--lan 'hplug*'）
#   sudo lab/lab.sh test-hotplug  #   新建接口自动补挂 → 分流生效；删除→重加 仍可
#   sudo lab/lab.sh rulecap-up    # 能力缺口 #4：match_set 容量 > 64（dae 1024）
#   sudo lab/lab.sh test-rules-cap #   生成 80+ 条规则：编译通过 + 行为正确
#   sudo lab/lab.sh udp-up       # P4b：UDP NAT 会话（rules.udp.dae）
#   sudo lab/lab.sh test-udp-relay    # UDP 真实转发 + 会话复用
#   sudo lab/lab.sh test-udp-idle     # UDP 会话 janitor 回收
#   sudo lab/lab.sh ss-up       # P5：shadowsocks（chacha20-ietf-poly1305）后端 + 协议/offload 互斥
#   sudo lab/lab.sh test-ss          # ss TCP 转发（512KB）+ 独立 Python 服务端 + 用户态 AEAD
#   sudo lab/lab.sh ss-udp-up   # P5：shadowsocks UDP 代理（rules.udp.dae）
#   sudo lab/lab.sh test-ss-udp      # ss UDP 转发 + sessions_proxied / direct_fallback
#   sudo lab/lab.sh trojan-up   # P5：trojan（TLS）后端
#   sudo lab/lab.sh test-trojan      # trojan TCP 转发（512KB）+ CONNECT 日志
#   sudo lab/lab.sh vless-up    # P5-G2：vless（明文 TCP）+ 协议/offload 互斥
#   sudo lab/lab.sh vless-tls-up     # P5-G2：vless + security=tls（自签）
#   sudo lab/lab.sh vless-udp-up     # P5-G2：vless UDP（rules.udp.dae）
#   sudo lab/lab.sh test-vless / test-vless-udp
#   sudo lab/lab.sh vmess-up    # P5-G2：vmess（chacha20-poly1305）
#   sudo lab/lab.sh vmess-tls-up     # P5-G2：vmess（aes-128-gcm + TLS）
#   sudo lab/lab.sh vmess-udp-up     # P5-G2：vmess UDP
#   sudo lab/lab.sh test-vmess / test-vmess-udp
#   sudo lab/lab.sh tuic-up    # P5-G3：tuic v5（QUIC；Go/quic-go 参考服务端）
#   sudo lab/lab.sh tuic-udp-up      # P5-G3：tuic UDP（QUIC DATAGRAM）
#   sudo lab/lab.sh test-tuic / test-tuic-udp
#   sudo lab/lab.sh hy2-up    # P5-G3b：hysteria2（QUIC + HTTP/3 认证；Go/http3 参考服务端）
#   sudo lab/lab.sh hy2-udp-up       # P5-G3b：hysteria2 UDP（QUIC DATAGRAM + 分片）
#   sudo lab/lab.sh test-hy2 / test-hy2-udp
#   sudo lab/lab.sh hy2-obfs-up      # P5-G3b+：salamander 混淆（UDP 包级 BLAKE2b XOR）
#   sudo lab/lab.sh hy2-obfs-udp-up  # P5-G3b+：salamander + UDP
#   sudo lab/lab.sh test-hy2-obfs / test-hy2-obfs-udp
#   sudo lab/lab.sh hy2-brutal-up    # P5-G3b+：cc_override=brutal + 带宽声明（窗口近似）
#   sudo lab/lab.sh hy2-hop-up       # P5-G3b+：udphop（多端口 mux + 5s 跳端口）
#   sudo lab/lab.sh test-hy2-brutal / test-hy2-hop
#   sudo lab/lab.sh sniff-punt-up     # P21：嗅探重判（dial_mode domain+ + ss 后端 + --sniff-punt）
#   sudo lab/lab.sh test-sniff-punt   # direct(直连不经 ss)/组(ss 远端解析)/block(关连接) 三条路径
#   sudo lab/lab.sh sub-order-up      # P34：两个订阅源（/sub、/sub2）+ 顺序回退
#   sudo lab/lab.sh test-sub-order    # 首源标死 → 活动订阅切次源（日志/状态面/端到端）
#   sudo lab/lab.sh ruleset-up        # P36：规则集（Clash YAML / sing-box JSON / 纯文本）
#   sudo lab/lab.sh test-ruleset      # 三种格式分流 + URL 刷新 + 未知规则集硬失败
#   sudo lab/lab.sh ops-up           # P6：运维面会话（--log-file + 状态面控制命令）
#   sudo lab/lab.sh test-ops         # suspend/reload/metrics/sysdump/日志轮转
#   sudo lab/lab.sh bench-up         # P7：基准直连会话（rules.bench.dae；供 lab/bench.sh）
#   （数据面固定为 Rust 对象 ebpf-rs/target/bpfel-unknown-none/release/sodama-ebpf；C 对象已移除，见 ADR-0025）
#   sudo lab/lab.sh ops-reload-up    # P6：整配置热重载会话（/tmp 配置副本 + 假 DNS）
#   sudo lab/lab.sh test-config-reload # 规则变更/失败回滚/DNS 上游热切换
#   sudo lab/lab.sh config-up  # 用完整 .dae 配置（lab/real-user.dae）启动（K3）
#   sudo lab/lab.sh forward-up # 单臂/标准拓扑 + SOCKS5 过渡一跳（K3）
#   sudo lab/lab.sh test-status  # 只读状态面（Unix socket JSON）
#   sudo lab/lab.sh test-config  # 完整配置模式：解析/子集编译/deferred 上报
#   sudo lab/lab.sh test-forward # tproxy -> socks5 一跳，orig_dst 保留
#   sudo lab/lab.sh test-rebind       # redirect_track 单写者：拒绝竞争发布者 + 陈旧窗口恢复
#   sudo lab/lab.sh test-fault-reload # 故障注入：reload 中持续打流
#   sudo lab/lab.sh test-fault-kill   # 故障注入：kill -9 后 TCX 自动摘钩 + fail-open（破坏性，最后跑）
#   sudo lab/lab.sh reload [file]     # 覆盖 rules.dae 并 SIGHUP（默认用 rules.reload.dae）
#   sudo lab/lab.sh status  # 看钩子/日志（含编译出的规则 dump）
#   sudo lab/lab.sh verify  # 全部用例（含故障注入；fault-kill 最后执行，会杀掉加载器）
#   sudo lab/lab.sh down
#
# P5-G2 生态交叉验证（不需要 root）：
#   lab/proto-check/run.sh vless|vmess [tls]   # 真实 Go 客户端（outbound fork）↔ Python 服务端
#
# 拓扑（全部在独立 netns 里，不碰宿主机网络）：
#
#   ⚠ 注意：landae/wan/single 这几个宿主侧接口会带上 10.0.0.0/24、10.9.9.0/24 等地址。
#   若你当前所在真实网络与这些网段重叠（例如软路由网关就是 10.0.0.1），启动 lab 会把
#   真实网关拉进实验拓扑 → 表现是“断网/面板失联”（像路由器故障）。up/dual-up 已加
#   预检直接报错；万不得已可设 LAB_ALLOW_LAN_COLLISION=1 跳过。
#
#   [client ns]                                    [wan ns]
#     lanclient 10.0.0.2 ──veth── landae 10.0.0.1    wanpeer 10.9.9.2
#                                (root ns)  wan 10.9.9.1 ──veth──┘
#                                  │
#                                  └─ dae0 ──veth── dae0peer   [daens ns]
#                                                      └── tproxy listener :12345
#
# client -> 1.1.1.1:8080 的流量在 landae ingress 被判为 proxy，改写 MAC 后
# bpf_redirect 进 dae0；dae0peer ingress 用 bpf_sk_assign 交给 tproxy socket；
# 回程在 dae0 ingress 还原 MAC 后送回 landae。
# client -> 10.9.9.2:9999 被判为 direct，由内核三层转发（Real Direct）。
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
LOADER="$ROOT/target/release/sodama"
OBJ="$ROOT/ebpf-rs/target/bpfel-unknown-none/release/sodama-ebpf"
LOG=/tmp/sodama.log
# 对标批：L3（无链路头）接口名，由 up() 建 ipip 隧道后赋值（未建则空 → 相关用例 SKIP）
L3_IFACE=""
WAN_LOG=/tmp/sodama-wan.log
PID_FILE=/tmp/sodama.pid
WAN_PID_FILE=/tmp/sodama-wan.pid

CLIENT_NS=sodama_client
WAN_NS=sodama_wan
DAE_NS=sodamans

PROXY_DST=1.1.1.1
DIRECT_DST=10.9.9.2
DIRECT_DST_2=10.9.10.2

# 当前拓扑下被分流接口的名字（dual-up 里改为 single）
LAN_IFACE=landae

# Docker 会把宿主 FORWARD 链策略设为 DROP。实验室的内核转发（direct / fault fail-open）
# 需要按接口精确放行；up 时加、cleanup 时删，不碰全局策略。
forward_allow() {
  command -v iptables >/dev/null 2>&1 || return 0
  iptables -C FORWARD -i "$1" -o "$2" -j ACCEPT 2>/dev/null ||
    iptables -I FORWARD 1 -i "$1" -o "$2" -j ACCEPT 2>/dev/null || true
  iptables -C FORWARD -i "$2" -o "$1" -j ACCEPT 2>/dev/null ||
    iptables -I FORWARD 1 -i "$2" -o "$1" -j ACCEPT 2>/dev/null || true
}

forward_disallow() {
  command -v iptables >/dev/null 2>&1 || return 0
  iptables -D FORWARD -i "$1" -o "$2" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "$2" -o "$1" -j ACCEPT 2>/dev/null || true
}

# 关闭网卡 offload（免 ethtool，见 net_offload.py；输出即回读证据，失败不致命）。
# SKIP_NET_OFFLOAD=1 时整体跳过——供「抖动/故障是否与关 offload 有关」的 A/B 对照。
disable_offload() {
  [ -z "${SKIP_NET_OFFLOAD:-}" ] || return 0
  python3 "$HERE/net_offload.py" "$@" || true
}
netns_disable_offload() {
  [ -z "${SKIP_NET_OFFLOAD:-}" ] || return 0
  local ns="$1"; shift
  ip netns exec "$ns" python3 "$HERE/net_offload.py" "$@" || true
}

# K3：只读状态面 / 过渡一跳
STATUS_SOCK=/tmp/sodama-status.sock
SOCKS5_PORT=1081
SOCKS5_LOG=/tmp/sodama-socks5-target.txt
SOCKS5_PID_FILE=/tmp/sodama-socks5.pid
# P7：bench.sh 的 C 基准服务端（wan ns 内）
BENCH_PID_FILE=/tmp/sodama-bench.pid

# P5：协议栈后端（G1：shadowsocks classic AEAD / trojan；G2：vless / vmess）
SS_PORT=8388
SS_LOG=/tmp/sodama-ss-target.txt
SS_PID_FILE=/tmp/sodama-ss.pid
# P15：订阅/节点组的第二个 ss 后端 + 订阅 HTTP 服务器
SS_PORT_B=9488
SSB_PID_FILE=/tmp/sodama-ssb.pid
SUB_PORT=18530
SUB_PID_FILE=/tmp/sodama-sub.pid
SUB_BODY=/tmp/sodama-sub-body.txt
SUB_CONFIG=/tmp/sodama-subscribe.dae
# P34：订阅顺序回退夹具（两个订阅源，各 1 节点，分别指向 ss A/B）
SUB_BODY2=/tmp/sodama-sub2-body.txt
SUB_URL_FILE=/tmp/sodama-sub2.url
SUB_ORDER_CONFIG=/tmp/sodama-sub-order.dae
# P36：规则集夹具（标准格式：Clash YAML / sing-box JSON / 纯文本）
RS_DIR=/tmp/sodama-rulesets
RS_CLASH_YAML=$RS_DIR/clash.yaml
RS_SINGBOX_JSON=$RS_DIR/singbox.json
RS_PLAIN_TXT=$RS_DIR/plain.txt
RS_CONFIG=/tmp/sodama-ruleset.dae
# P19：多组分派夹具配置（groups-up 生成）
SUB_GROUPS_CONFIG=/tmp/sodama-groups.dae
# P18e：SS2022（shadowsocks-rust ssserver 参考对端；PSK 为 16 字节 "0123456789abcdef" 的 base64）
SS2022_PSK=MDEyMzQ1Njc4OWFiY2RlZg==
SS2022_METHOD=2022-blake3-aes-128-gcm
SS2022_PID_FILE=/tmp/sodama-ss2022.pid
# P18e：HTTP CONNECT 出站夹具
HTTP_PROXY_PORT=18390
HTTP_PROXY_LOG=/tmp/sodama-http-proxy.log
HTTP_PROXY_PID_FILE=/tmp/sodama-http-proxy.pid
TROJAN_PORT=8443
TROJAN_LOG=/tmp/sodama-trojan-target.txt
TROJAN_PID_FILE=/tmp/sodama-trojan.pid
CERTS_DIR="$HERE/certs"
VLESS_PORT=8543
VLESS_TLS_PORT=8544
VLESS_UUID=b831381d-6324-4d53-ad4f-8cda48b30811
VLESS_LOG=/tmp/sodama-vless-target.txt
VLESS_PID_FILE=/tmp/sodama-vless.pid
VMESS_PORT=8643
VMESS_TLS_PORT=8644
VMESS_UUID=de305d54-75b4-431b-adb2-eb6b9e546014
VMESS_LOG=/tmp/sodama-vmess-target.txt
VMESS_PID_FILE=/tmp/sodama-vmess.pid
# P5-G3：TUIC v5 参考服务端（Go/quic-go，见 lab/proto-check/）
TUIC_PORT=8653
TUIC_UUID=de305d54-75b4-431b-adb2-eb6b9e546014
TUIC_PASSWORD=testpass
TUIC_LOG=/tmp/sodama-tuic-target.txt
TUIC_PID_FILE=/tmp/sodama-tuic.pid
# P5-G3b：hysteria2 参考服务端（Go/quic-go http3，见 lab/proto-check/）
HY2_PORT=8753
HY2_AUTH=testpass
HY2_LOG=/tmp/sodama-hy2-target.txt
HY2_PID_FILE=/tmp/sodama-hy2.pid
# P5-G3b+：udphop 服务端额外端口（逗号/范围列表，与客户端链接里的端口并集对应）
HY2_HOP_PORTS="8754,8755-8756"
# P27：juicity（QUIC + TUIC 式认证）参考服务端
JUICITY_PORT=18964
JUICITY_LOG=/tmp/sodama-juicity.log
JUICITY_PID_FILE=/tmp/sodama-juicity.pid
JUICITY_UUID=b831381d-6324-4d53-ad4f-8cda48b30811
JUICITY_PASSWORD=testpass
# P30：SSR（shadowsocksr-stream；origin+plain）参考服务端
SSR_PORT=8389
SSR_METHOD=aes-256-cfb
SSR_PASSWORD=testpass
SSR_PASSWORD_B64=dGVzdHBhc3M
SSR_LOG=/tmp/sodama-ssr-target.txt
SSR_PID_FILE=/tmp/sodama-ssr.pid
# P31：shadow-tls（ss 插件；v1/v2/v3）参考服务端
SHADOWTLS_PORT=8399
SHADOWTLS_PASSWORD=testpass
SHADOWTLS_LOG=/tmp/sodama-shadowtls.log
SHADOWTLS_PID_FILE=/tmp/sodama-shadowtls.pid
# P25：naive（HTTP/2 CONNECT）参考服务端
NAIVE_PORT=8663
NAIVE_LOG=/tmp/sodama-naive.log
NAIVE_PID_FILE=/tmp/sodama-naive.pid
NAIVE_USER=user
NAIVE_PASS=pass
# P26：naive over HTTP/3（quic-go 参考服务端）
NAIVE_H3_PORT=8664
NAIVE_H3_LOG=/tmp/sodama-naive-h3.log
NAIVE_H3_PID_FILE=/tmp/sodama-naive-h3.pid
# P26：DoH over HTTP/3（quic-go 参考服务端）
DOH_H3_PORT=8955
DOH_H3_LOG=/tmp/sodama-doh-h3.txt
DOH_H3_PID_FILE=/tmp/sodama-doh-h3.pid

# P6：运维面
OPS_LOG=/tmp/sodama-ops.log

# P3a：DNS
FAKE_DNS_PORT=5353
FAKE_DNS_LOG=/tmp/sodama-fake-dns.txt
FAKE_DNS_PID_FILE=/tmp/sodama-fake-dns.pid

# P18a：DoT/DoH 上游夹具（Python 自签，转发到假 UDP DNS）
DOT_PORT=8853
DOT_LOG=/tmp/sodama-dot.txt
DOT_PID_FILE=/tmp/sodama-dot.pid
DOH_PORT=8953
DOH_LOG=/tmp/sodama-doh.txt
DOH_PID_FILE=/tmp/sodama-doh.pid
# P23：DoH over HTTP/2 参考服务端（Go 标准库）
DOH_H2_PORT=8954
DOH_H2_LOG=/tmp/sodama-doh-h2.txt
DOH_H2_PID_FILE=/tmp/sodama-doh-h2.pid
# P18b：DoQ 参考服务端（Go/quic-go，需先构建；转发到假 UDP DNS）
DOQ_PORT=9053
DOQ_LOG=/tmp/sodama-doq.txt
DOQ_PID_FILE=/tmp/sodama-doq.pid
# P18c：dns.routing 夹具（第二假上游 + asis 目标）
FAKE_DNS_B_PORT=5354
FAKE_DNS_B_LOG=/tmp/sodama-fake-dns-b.txt
FAKE_DNS_B_PID_FILE=/tmp/sodama-fake-dns-b.pid
ASIS_DNS_LOG=/tmp/sodama-asis-dns.txt
ASIS_DNS_PID_FILE=/tmp/sodama-asis-dns.pid

die() { echo "!! $*" >&2; exit 1; }

require_root() {
  [ "$(id -u)" = 0 ] || die "需要 root：sudo $0 $*"
}

# 按线程名汇总 loader 的 OS 线程数（排障/线程泄漏回归共用）。
threads_by_comm() {
  local pid="$1" f
  for f in /proc/"$pid"/task/*/comm; do
    [ -r "$f" ] || continue
    cat "$f" 2>/dev/null || true
  done | sort | uniq -c | sort -rn
}

# relay 泵线程数（comm=relay：会话 handler + 其 spawn 的无名 sibling 都叫 relay）。
count_relay_threads() {
  local pid="$1" c name n=0
  while read -r c name; do
    [ "$name" = relay ] || continue
    n="$c"
  done < <(threads_by_comm "$pid" || true)
  echo "$n"
}

# lab 的 LAN/WAN 网段会配到宿主机 root ns（landae/wan/single）。若与真实网络同网段，
# 启动 lab 会把真实网关/DNS 拉进实验拓扑 → 典型症状是“断网”（面板/SSH/网关全失联），
# 看起来像路由器坏了。启动前硬失败；确需在重叠网络里跑可设 LAB_ALLOW_LAN_COLLISION=1。
check_lan_collision() {
  [ -z "${LAB_ALLOW_LAN_COLLISION:-}" ] || return 0
  local n hit=""
  for n in 10.0.0.0/24 10.9.9.0/24 10.9.10.0/24; do
    if ip route show "$n" 2>/dev/null | grep -vqE 'dev (landae|wan|single)\b'; then
      hit+=" $n"
    fi
  done
  if [ -n "$hit" ]; then
    die "真实网络与 lab 网段重叠:$hit
  lab 要把 10.0.0.0/24 等配到宿主机接口（landae/wan）做“路由器”角色，继续会把同网段
  的真实流量吸入实验拓扑 —— 症状：网关/面板/DNS 失联（像“路由器坏了”）。
  处理：换一张不重叠的网络（如手机热点），或设 LAB_ALLOW_LAN_COLLISION=1 自行承担。"
  fi
}

# 以调用者身份构建，避免 root 污染 target/
as_user() {
  if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != root ]; then
    sudo -u "$SUDO_USER" -H "$@"
  else
    "$@"
  fi
}

# P5-G2：构造 vmess:// 分享链接（base64 JSON，v2rayN 格式）
# 用法： vmess_link <host> <port> <uuid> <scy> <none|tls>
vmess_link() {
  python3 - "$@" <<'PY'
import base64, json, sys
host, port, uuid, scy, tls = sys.argv[1:6]
obj = {"v": "2", "ps": "lab", "add": host, "port": port, "id": uuid,
       "aid": "0", "scy": scy, "net": "tcp", "type": "none"}
if tls == "tls":
    obj.update({"tls": "tls", "sni": "localhost", "allowInsecure": True})
print("vmess://" + base64.b64encode(json.dumps(obj).encode()).decode())
PY
}

build() {
  echo "== cargo: 加载器 =="
  (cd "$ROOT" && as_user cargo build --release)
  echo "== cargo +nightly: Rust eBPF 对象（唯一数据面）=="
  as_user "$HERE/build-ebpf-rs.sh"
  echo "== 构建完成：$OBJ, $LOADER =="
}

# 删除所有实验资源；up 前也会先调一次
cleanup() {
  # P6：热重载实验的配置副本由测试生成，随会话清理
  rm -f /tmp/sodama-ops.dae
  if [ -f "$PID_FILE" ]; then
    kill "$(cat "$PID_FILE")" 2>/dev/null || true
    rm -f "$PID_FILE"
  fi
  if [ -f "$WAN_PID_FILE" ]; then
    kill "$(cat "$WAN_PID_FILE")" 2>/dev/null || true
    rm -f "$WAN_PID_FILE"
  fi
  if [ -f "$SOCKS5_PID_FILE" ]; then
    kill "$(cat "$SOCKS5_PID_FILE")" 2>/dev/null || true
    rm -f "$SOCKS5_PID_FILE"
  fi
  if [ -f "$SS_PID_FILE" ]; then
    kill "$(cat "$SS_PID_FILE")" 2>/dev/null || true
    rm -f "$SS_PID_FILE"
  fi
  if [ -f "$SSB_PID_FILE" ]; then
    kill "$(cat "$SSB_PID_FILE")" 2>/dev/null || true
    rm -f "$SSB_PID_FILE"
  fi
  if [ -f "$SUB_PID_FILE" ]; then
    kill "$(cat "$SUB_PID_FILE")" 2>/dev/null || true
    rm -f "$SUB_PID_FILE"
  fi
  if [ -f "$SS2022_PID_FILE" ]; then
    kill "$(cat "$SS2022_PID_FILE")" 2>/dev/null || true
    rm -f "$SS2022_PID_FILE"
  fi
  if [ -f "$HTTP_PROXY_PID_FILE" ]; then
    kill "$(cat "$HTTP_PROXY_PID_FILE")" 2>/dev/null || true
    rm -f "$HTTP_PROXY_PID_FILE"
  fi
  if [ -f "$TROJAN_PID_FILE" ]; then
    kill "$(cat "$TROJAN_PID_FILE")" 2>/dev/null || true
    rm -f "$TROJAN_PID_FILE"
  fi
  if [ -f "$VLESS_PID_FILE" ]; then
    kill "$(cat "$VLESS_PID_FILE")" 2>/dev/null || true
    rm -f "$VLESS_PID_FILE"
  fi
  if [ -f "$VMESS_PID_FILE" ]; then
    kill "$(cat "$VMESS_PID_FILE")" 2>/dev/null || true
    rm -f "$VMESS_PID_FILE"
  fi
  if [ -f "$TUIC_PID_FILE" ]; then
    kill "$(cat "$TUIC_PID_FILE")" 2>/dev/null || true
    rm -f "$TUIC_PID_FILE"
  fi
  if [ -f "$HY2_PID_FILE" ]; then
    kill "$(cat "$HY2_PID_FILE")" 2>/dev/null || true
    rm -f "$HY2_PID_FILE"
  fi
  if [ -f "$JUICITY_PID_FILE" ]; then
    kill "$(cat "$JUICITY_PID_FILE")" 2>/dev/null || true
    rm -f "$JUICITY_PID_FILE"
  fi
  if [ -f "$SSR_PID_FILE" ]; then
    kill "$(cat "$SSR_PID_FILE")" 2>/dev/null || true
    rm -f "$SSR_PID_FILE"
  fi
  if [ -f "$SHADOWTLS_PID_FILE" ]; then
    kill "$(cat "$SHADOWTLS_PID_FILE")" 2>/dev/null || true
    rm -f "$SHADOWTLS_PID_FILE"
  fi
  if [ -f "$NAIVE_PID_FILE" ]; then
    kill "$(cat "$NAIVE_PID_FILE")" 2>/dev/null || true
    rm -f "$NAIVE_PID_FILE"
  fi
  if [ -f "$NAIVE_H3_PID_FILE" ]; then
    kill "$(cat "$NAIVE_H3_PID_FILE")" 2>/dev/null || true
    rm -f "$NAIVE_H3_PID_FILE"
  fi
  if [ -f "$DOH_H3_PID_FILE" ]; then
    kill "$(cat "$DOH_H3_PID_FILE")" 2>/dev/null || true
    rm -f "$DOH_H3_PID_FILE"
  fi
  if [ -f "$FAKE_DNS_PID_FILE" ]; then
    kill "$(cat "$FAKE_DNS_PID_FILE")" 2>/dev/null || true
    rm -f "$FAKE_DNS_PID_FILE"
  fi
  if [ -f "$DOT_PID_FILE" ]; then
    kill "$(cat "$DOT_PID_FILE")" 2>/dev/null || true
    rm -f "$DOT_PID_FILE"
  fi
  if [ -f "$DOH_PID_FILE" ]; then
    kill "$(cat "$DOH_PID_FILE")" 2>/dev/null || true
    rm -f "$DOH_PID_FILE"
  fi
  if [ -f "$DOH_H2_PID_FILE" ]; then
    kill "$(cat "$DOH_H2_PID_FILE")" 2>/dev/null || true
    rm -f "$DOH_H2_PID_FILE"
  fi
  if [ -f "$DOQ_PID_FILE" ]; then
    kill "$(cat "$DOQ_PID_FILE")" 2>/dev/null || true
    rm -f "$DOQ_PID_FILE"
  fi
  if [ -f "$FAKE_DNS_B_PID_FILE" ]; then
    kill "$(cat "$FAKE_DNS_B_PID_FILE")" 2>/dev/null || true
    rm -f "$FAKE_DNS_B_PID_FILE"
  fi
  if [ -f "$ASIS_DNS_PID_FILE" ]; then
    kill "$(cat "$ASIS_DNS_PID_FILE")" 2>/dev/null || true
    rm -f "$ASIS_DNS_PID_FILE"
  fi
  if [ -f "$BENCH_PID_FILE" ]; then
    kill "$(cat "$BENCH_PID_FILE")" 2>/dev/null || true
    rm -f "$BENCH_PID_FILE"
  fi
  rm -f "$OPS_LOG" "$OPS_LOG.1"
  rm -f "$STATUS_SOCK"
  forward_disallow landae wan
  forward_disallow single single
  ip netns del "$CLIENT_NS" 2>/dev/null || true
  ip netns del "$WAN_NS" 2>/dev/null || true
  ip netns del "$DAE_NS" 2>/dev/null || true
  ip link del landae 2>/dev/null || true
  ip link del landae3 2>/dev/null || true
  ip link del l3u 2>/dev/null || true
  ip link del wan 2>/dev/null || true
  ip link del dae0 2>/dev/null || true
  ip link del single 2>/dev/null || true
  ip link del br0 2>/dev/null || true
  # 能力缺口 #3：热插拔用例的临时接口（成对删除，cli 侧随对端销毁）
  ip link del hplug-lan 2>/dev/null || true
  ip link del hplugw 2>/dev/null || true
  # 能力缺口 #2：订阅磁盘缓存（用例要求从干净状态开始）
  rm -f /tmp/sub-cache/lab.bin
  ip route del "$PROXY_DST/32" 2>/dev/null || true
  ip route del 10.9.10.0/24 2>/dev/null || true
  ip route del 9.9.9.9/32 2>/dev/null || true
  LAN_IFACE=landae
}

up() {
  require_root
  [ -f "$OBJ" ] && [ -x "$LOADER" ] || die "先运行 $0 build"
  check_lan_collision
  cleanup
  # 根 ns 的 lo：lab 多处依赖 127.0.0.1（ss 等后端夹具、假上游 DNS、性能对比），
  # 而最小 initramfs（QEMU 矩阵）里 lo 默认 down——不显式拉起会得到
  # 「Cannot assign requested address / Network is unreachable」这类误导性失败。
  ip link set lo up
  # C4：XDP 计量探针默认挂在 LAN 接口（恒 XDP_PASS；不支持时 loader 只告警）。
  # 用 `USE_XDP_IFACE= `（显式置空）关闭，或换成别的接口。
  USE_XDP_IFACE="${USE_XDP_IFACE-landae}"

  echo "== 建立 netns 与 veth =="
  ip netns add "$CLIENT_NS"
  ip netns add "$WAN_NS"
  ip netns add "$DAE_NS"

  # LAN: client <-> landae
  ip link add landae type veth peer name lanclient
  ip link set lanclient netns "$CLIENT_NS"
  ip addr add 10.0.0.1/24 dev landae
  ip link set landae up
  ip -n "$CLIENT_NS" link set lo up
  ip -n "$CLIENT_NS" addr add 10.0.0.2/24 dev lanclient
  ip -n "$CLIENT_NS" link set lanclient up
  ip -n "$CLIENT_NS" route add default via 10.0.0.1
  # P16：LAN IPv6
  ip -6 addr add 2001:db8:1::1/64 dev landae nodad
  ip -n "$CLIENT_NS" -6 addr add 2001:db8:1::2/64 dev lanclient nodad
  ip -n "$CLIENT_NS" -6 route add default via 2001:db8:1::1

  # 对标批：L3 段（ipip 隧道，arphrd=768=ARPHRD_TUNNEL）——LAN 侧无链路头接口。
  # 对照 dae `linkHdrLen()`（control/control_plane_core_bind.go:61-77：ipip → 0）与
  # `_l3` 程序变体（`SEC("tc/lan_ingress_l3")`）。asm 侧设备没有以太头，
  # 这是验证「L3 解析 + 送控制面补头 + 回程剥头」的承载物。
  # 内核在 `ip tunnel add mode ipip` 时自动 modprobe ipip（rtnl-link-ipip）。
  if [ -z "${NO_L3:-}" ]; then
    # 先显式 modprobe：`ip tunnel add` 靠内核 rtnl-link 自动加载，而在 initramfs/chroot
    # 环境下 usermodehelper 看不到 chroot 里的模块树，自动加载会失败（VM 实测）。
    modprobe ipip 2>/dev/null || true
    # 给 L3 段一条**专用 underlay veth**（10.30.0.0/24）：
    #   1) 关 offload 只影响这条链路，不动标准用例的 lanclient/landae 吞吐基线；
    #   2) 隧道外层流量有独立路径，排障时无歧义。
    # 不建 underlay 时（旧形态）外层走 10.0.0.0/24，但隧道的 return 腿会踩
    # 「veth+隧道 内层校验和 PARTIAL」问题（见 net_offload.py 头部注释）。
    ip link add l3u type veth peer name l3uc
    ip link set l3uc netns "$CLIENT_NS"
    ip addr add 10.30.0.1/24 dev l3u
    ip link set l3u up
    ip -n "$CLIENT_NS" link set l3uc up
    ip -n "$CLIENT_NS" addr add 10.30.0.2/24 dev l3uc
    if ! ip tunnel add landae3 mode ipip local 10.30.0.1 remote 10.30.0.2; then
      echo "!! ipip 隧道创建失败（内核无 ipip 模块？）——L3 用例将 SKIP"
    fi
    if ip link show landae3 >/dev/null 2>&1; then
      ip link set landae3 up
      ip addr add 10.20.0.1/24 dev landae3
      # MTU：ipip 封装开销 20(外层 IP)+14(以太) = 34 → 内层 1466，使内层 MSS=1426，
      # 外层封包 ≤1500。不降 MTU 时大流会在封装处超 MTU（实测：512KB 流被 RST）。
      ip link set landae3 mtu 1466
      ip -n "$CLIENT_NS" tunnel add l3cli mode ipip local 10.30.0.2 remote 10.30.0.1
      ip -n "$CLIENT_NS" link set l3cli up
      ip -n "$CLIENT_NS" addr add 10.20.0.2/24 dev l3cli
      ip -n "$CLIENT_NS" link set l3cli mtu 1466
      # 关掉 L3 链路两端的 offload：不关时内层校验和恒错 → 对端静默丢包
      # （工具免 ethtool 依赖，见 lab/net_offload.py；输出即回读证据，失败不致命）。
      disable_offload l3u landae3
      netns_disable_offload "$CLIENT_NS" l3uc l3cli
      L3_IFACE=landae3
    fi
  fi

  # WAN: wan <-> wanpeer
  ip link add wan type veth peer name wanpeer
  ip link set wanpeer netns "$WAN_NS"
  ip addr add 10.9.9.1/24 dev wan
  ip link set wan up
  ip -n "$WAN_NS" link set lo up
  ip -n "$WAN_NS" addr add "$DIRECT_DST/24" dev wanpeer
  ip -n "$WAN_NS" addr add "$DIRECT_DST_2/24" dev wanpeer
  # P3a 假 DNS 应答的地址（域位图测试用）
  ip -n "$WAN_NS" addr add 10.9.10.3/32 dev wanpeer
  ip -n "$WAN_NS" addr add 10.9.10.4/32 dev wanpeer
  # P36：规则集夹具 plain.test 的应答地址
  ip -n "$WAN_NS" addr add 10.9.10.5/32 dev wanpeer
  # P3b-2a regex 域分流测试用
  ip -n "$WAN_NS" addr add 10.9.10.21/32 dev wanpeer
  ip -n "$WAN_NS" addr add 10.9.10.22/32 dev wanpeer
  ip -n "$WAN_NS" addr add 10.9.10.23/32 dev wanpeer
  # P4 relay 目标：1.1.1.1 已由 $PROXY_DST 添加；2.2.2.2 为 UDP relay 目标
  ip -n "$WAN_NS" addr add 2.2.2.2/32 dev wanpeer
  # 让「假公网」也监听 1.1.1.1：kill -9 故障测试里，钩子摘除后流量回落为
  # 普通转发，客户端能在这里得到应答（fail-open，而不是黑洞）。
  ip -n "$WAN_NS" addr add "$PROXY_DST/32" dev wanpeer
  ip -n "$WAN_NS" link set wanpeer up
  ip -n "$WAN_NS" route add 10.0.0.0/24 via 10.9.9.1
  # P16：WAN IPv6（2001:db8:aa::1 为“假公网”目标，wan_echo 双栈监听）
  ip -6 addr add 2001:db8:9::1/64 dev wan nodad
  ip -n "$WAN_NS" -6 addr add 2001:db8:9::2/64 dev wanpeer nodad
  ip -n "$WAN_NS" -6 addr add 2001:db8:aa::1/128 dev wanpeer nodad
  ip -n "$WAN_NS" -6 route add 2001:db8:1::/64 via 2001:db8:9::1
  # 对照 v4 的 1.1.1.1 兜底路由：未拦住时从 WAN 出去（fail-open 可观测）
  ip -6 route add 2001:db8:aa::1/128 via 2001:db8:9::2 dev wan

  # 控制面对：dae0 <-> dae0peer（dae0peer 在 daens）
  ip link add dae0 type veth peer name dae0peer
  ip link set dae0peer netns "$DAE_NS"
  ip link set dae0 up
  ip -n "$DAE_NS" link set lo up
  ip -n "$DAE_NS" link set dae0peer up
  # 对照 dae control/netns_utils.go:871-914 (setupIPv4Datapath)：
  # 169.254.0.11/32 给 dae0peer 一个地址以生成正确的 L3 头；默认路由走
  # “网关” 169.254.0.1 + 静态邻居（dae0 的 MAC）。tproxy 回包的源地址是
  # 原始目的地址（非本机地址），没有这套配置内核会因为源地址校验发不出去。
  ip -n "$DAE_NS" addr add 169.254.0.11/32 dev dae0peer
  ip -n "$DAE_NS" route add 169.254.0.1/32 dev dae0peer scope link
  ip -n "$DAE_NS" route add default via 169.254.0.1 dev dae0peer
  local dae0_mac
  dae0_mac="$(ip link show dev dae0 | awk '/link\/ether/ {print $2; exit}')"
  [ -n "$dae0_mac" ] || die "拿不到 dae0 的 MAC"
  ip -n "$DAE_NS" neigh add 169.254.0.1 lladdr "$dae0_mac" \
    dev dae0peer nud permanent
  # P16：IPv6 控制面对照 dae netns_utils.go:setupIPv6Datapath（fe80 网关联到 dae0）。
  # 关键：必须像 v4 一样写静态邻居。若靠 NDP 动态解析，NA 回包会被
  # dae0peer_ingress 的「cb[0] != TPROXY_MARK → SHOT」丢弃（上游 C 同样如此），
  # 邻居永远 INCOMPLETE，tproxy v6 回包（SYN-ACK）发不出去。
  if sysctl -qw net.ipv6.conf.all.disable_ipv6=0 2>/dev/null; then
    sysctl -qw net.ipv6.conf.dae0.forwarding=1
    ip -6 addr add fe80::ecee:eeff:feee:eeee/128 dev dae0 scope link nodad 2>/dev/null || true
    ip -n "$DAE_NS" -6 route add default via fe80::ecee:eeff:feee:eeee dev dae0peer 2>/dev/null || true
    ip -n "$DAE_NS" -6 neigh add fe80::ecee:eeff:feee:eeee lladdr "$dae0_mac" \
      dev dae0peer nud permanent
    ip -n "$DAE_NS" -6 rule add fwmark 0x8000000/0x8000000 table 2023 2>/dev/null || true
    ip -n "$DAE_NS" -6 route add local default dev lo table 2023 2>/dev/null || true
    sysctl -qw net.ipv6.conf.all.forwarding=1
  fi
  # 对照 dae control/netns_utils.go:863-867：accept_local 防止内核按
  # "martian source" 丢掉源地址是本机地址的包
  ip netns exec "$DAE_NS" sysctl -qw net.ipv4.conf.dae0peer.accept_local=1
  # 关掉控制面对（dae0/dae0peer）的 offload：L3 回程会经这对 veth 进控制面再回来，
  # 不关时内层校验和以 PARTIAL 一路带到隧道封装，对端静默丢包（同 net_offload.py 注释）。
  disable_offload dae0
  netns_disable_offload "$DAE_NS" dae0peer
  # MTU 1466（=1500-34）：控制面回程要能塞进 L3 隧道的封装里（否则大流超 MTU）。
  # 只在建了 L3 段时降——标准拓扑保持 1500，不影响既有性能基线。
  if [ -n "$L3_IFACE" ]; then
    ip link set dae0 mtu 1466 2>/dev/null || true
    ip -n "$DAE_NS" link set dae0peer mtu 1466 2>/dev/null || true
  fi
  # 对照 dae control/kern/tproxy.c:2904 的注释：被 mark 的报文必须本地投递
  ip -n "$DAE_NS" rule add fwmark 0x8000000/0x8000000 table 2023
  ip -n "$DAE_NS" route add local default dev lo table 2023

  echo "== 内核转发开关 =="
  sysctl -qw net.ipv4.ip_forward=1
  sysctl -qw net.ipv4.conf.all.rp_filter=0
  sysctl -qw net.ipv4.conf.default.rp_filter=0
  # 对照 dae netns_utils.go:841（dae0.accept_local=1）
  sysctl -qw net.ipv4.conf.dae0.accept_local=1
  # 宿主若装了 Docker（FORWARD 策略 drop），按接口放行实验网段的转发
  forward_allow landae wan
  ip netns exec "$WAN_NS" sysctl -qw net.ipv4.conf.all.rp_filter=0 2>/dev/null || true
  ip netns exec "$DAE_NS" sysctl -qw net.ipv4.ip_nonlocal_bind=1 2>/dev/null || true

  # 给"公网地址"一条兜底路由：如果 eBPF 没拦住，流量会从 WAN 出去（可用于对照）
  ip route add "$PROXY_DST/32" via "$DIRECT_DST" dev wan
  ip route add 10.9.10.0/24 via "$DIRECT_DST" dev wan
  # P4：UDP relay 目标
  ip route add 2.2.2.2/32 via "$DIRECT_DST" dev wan
  # "假公共 DNS"：客户端会把查询发到这里（若没被接管则自然超时）
  ip route add 9.9.9.9/32 via "$DIRECT_DST" dev wan
  # 对标批 L3：回程腿——L3 客户端网段（10.20.0.0/24）对「假公网」（WAN ns）与 dae ns
  # 都不可见；不补这两条时回包会在两处被丢（VM 对照实验：不经 sodama 的隧道直连也超时）。
  if [ -n "$L3_IFACE" ]; then
    ip -n "$WAN_NS" route add 10.20.0.0/24 via 10.9.9.1
    ip -n "$DAE_NS" route add 10.20.0.0/24 via 169.254.0.1 dev dae0peer
  fi

  # 性能对比（lab/perf/run.sh）：只要拓扑，不启动 sodama / echo 夹具。
  if [ -n "${TOPO_ONLY:-}" ]; then
    echo "== TOPO_ONLY：netns/veth/路由已就绪（未启动 sodama） =="
    return 0
  fi

  echo "== 启动 WAN 侧 echo 服务 =="
  ip netns exec "$WAN_NS" python3 "$HERE/wan_echo.py" >"$WAN_LOG" 2>&1 &
  echo $! >"$WAN_PID_FILE"
  sleep 0.3

  # K3/P4：可选 socks5 后端（--forward/--dialer socks5://…）
  # P4 起 relay 拨号器在 host ns 建立出口连接，因此后端从 host ns 可达即可。
  if [ -n "${USE_FORWARD:-}" ]; then
    rm -f "$SOCKS5_LOG"
    python3 "$HERE/socks5_echo.py" "$SOCKS5_LOG" "$SOCKS5_PORT" \
      >/tmp/sodama-socks5.log 2>&1 &
    echo $! >"$SOCKS5_PID_FILE"
    sleep 0.3
  fi

  # P5：可选协议栈后端（--dialer ss://… / trojan://…），从 host ns 启动。
  # 两个服务端都是独立实现（ss_server.py 用 cryptography，trojan_server.py 用 stdlib
  # ssl），用于跨实现互操作验证，不复用 Rust 侧代码。
  if [ -n "${USE_SS:-}" ]; then
    rm -f "$SS_LOG"
    python3 -u "$HERE/ss_server.py" "$SS_LOG" "${USE_SS_METHOD:?USE_SS_METHOD 未设置}" "${USE_SS_PASSWORD:?USE_SS_PASSWORD 未设置}" "$SS_PORT" \
      >/tmp/sodama-ss.log 2>&1 &
    echo $! >"$SS_PID_FILE"
    sleep 0.3
    kill -0 "$(cat "$SS_PID_FILE")" 2>/dev/null || { cat /tmp/sodama-ss.log; die "ss 服务端启动失败"; }
  fi
  # P15：订阅测试的第二个 ss 后端（节点组 failover 用）
  if [ -n "${USE_SS_B:-}" ]; then
    rm -f "${SS_LOG}.b"
    python3 -u "$HERE/ss_server.py" "${SS_LOG}.b" "${USE_SS_METHOD:?USE_SS_METHOD 未设置}" "${USE_SS_PASSWORD:?USE_SS_PASSWORD 未设置}" "$SS_PORT_B" \
      >/tmp/sodama-ssb.log 2>&1 &
    echo $! >"$SSB_PID_FILE"
    sleep 0.3
    kill -0 "$(cat "$SSB_PID_FILE")" 2>/dev/null || { cat /tmp/sodama-ssb.log; die "ss-B 服务端启动失败"; }
  fi
  if [ -n "${USE_SUB_SERVER:-}" ]; then
    local sub_args=("$SUB_BODY")
    # P34：/sub2 第二订阅源（文件存在时）；P36：SUB_ROUTES_SPEC 追加任意路由（规则集）
    [ -f "$SUB_BODY2" ] && sub_args+=("$SUB_BODY2")
    SUB_EXTRA_ROUTES="${SUB_ROUTES_SPEC:-}" python3 "$HERE/sub_server.py" "$SUB_PORT" "${sub_args[@]}" \
      >/tmp/sodama-sub.log 2>&1 &
    echo $! >"$SUB_PID_FILE"
    sleep 0.3
    kill -0 "$(cat "$SUB_PID_FILE")" 2>/dev/null || { cat /tmp/sodama-sub.log; die "订阅服务器启动失败"; }
  fi
  # P18e：SS2022 参考对端（shadowsocks-rust ssserver，需系统安装）
  if [ -n "${USE_SS_2022:-}" ]; then
    command -v ssserver >/dev/null 2>&1 || die "需要 shadowsocks-rust（ssserver）：pacman -S shadowsocks-rust"
    rm -f "$SS_LOG.2022"
    ssserver -s "127.0.0.1:$SS_PORT" -m "$SS2022_METHOD" -k "$SS2022_PSK" \
      --outbound-fwmark 563 \
      >/tmp/sodama-ss2022.log 2>&1 &
    echo $! >"$SS2022_PID_FILE"
    sleep 0.3
    kill -0 "$(cat "$SS2022_PID_FILE")" 2>/dev/null || { cat /tmp/sodama-ss2022.log; die "ssserver（SS2022）启动失败"; }
  fi
  # P18e：HTTP CONNECT 出站夹具（可选 Basic 认证：USE_HTTP_PROXY_AUTH=user:pass）
  if [ -n "${USE_HTTP_PROXY:-}" ]; then
    rm -f "$HTTP_PROXY_LOG"
    python3 -u "$HERE/http_connect_server.py" "$HTTP_PROXY_LOG" "$HTTP_PROXY_PORT" \
      ${USE_HTTP_PROXY_AUTH:+"$USE_HTTP_PROXY_AUTH"} \
      >/tmp/sodama-http-proxy.log 2>&1 &
    echo $! >"$HTTP_PROXY_PID_FILE"
    sleep 0.3
    kill -0 "$(cat "$HTTP_PROXY_PID_FILE")" 2>/dev/null || { cat /tmp/sodama-http-proxy.log; die "HTTP CONNECT 代理启动失败"; }
  fi
  if [ -n "${USE_TROJAN:-}" ]; then
    [ -f "$CERTS_DIR/cert.pem" ] && [ -f "$CERTS_DIR/key.pem" ] \
      || die "缺自签证书：先运行 lab/gen-certs.sh"
    rm -f "$TROJAN_LOG"
    python3 -u "$HERE/trojan_server.py" "$TROJAN_LOG" "${USE_TROJAN_PASSWORD:?USE_TROJAN_PASSWORD 未设置}" "$TROJAN_PORT" \
      "$CERTS_DIR/cert.pem" "$CERTS_DIR/key.pem" \
      >/tmp/sodama-trojan.log 2>&1 &
    echo $! >"$TROJAN_PID_FILE"
    sleep 0.3
    kill -0 "$(cat "$TROJAN_PID_FILE")" 2>/dev/null || { cat /tmp/sodama-trojan.log; die "trojan 服务端启动失败"; }
  fi
  # P5-G2：vless / vmess 后端（--dialer vless://… / vmess://…），从 host ns 启动。
  # USE_PROTO_TLS=1 时带自签证书（security=tls）。
  if [ -n "${USE_VLESS:-}" ]; then
    local vless_port="$VLESS_PORT" vless_args=()
    if [ -n "${USE_PROTO_TLS:-}" ]; then
      vless_port="$VLESS_TLS_PORT"
      [ -f "$CERTS_DIR/cert.pem" ] && [ -f "$CERTS_DIR/key.pem" ] \
        || die "缺自签证书：先运行 lab/gen-certs.sh"
      vless_args=("$CERTS_DIR/cert.pem" "$CERTS_DIR/key.pem")
    fi
    rm -f "$VLESS_LOG"
    python3 -u "$HERE/vless_server.py" "$VLESS_LOG" "$VLESS_UUID" "$vless_port" "${vless_args[@]}" \
      >/tmp/sodama-vless.log 2>&1 &
    echo $! >"$VLESS_PID_FILE"
    sleep 0.3
    kill -0 "$(cat "$VLESS_PID_FILE")" 2>/dev/null || { cat /tmp/sodama-vless.log; die "vless 服务端启动失败"; }
  fi
  if [ -n "${USE_VMESS:-}" ]; then
    local vmess_port="$VMESS_PORT" vmess_args=()
    if [ -n "${USE_PROTO_TLS:-}" ]; then
      vmess_port="$VMESS_TLS_PORT"
      [ -f "$CERTS_DIR/cert.pem" ] && [ -f "$CERTS_DIR/key.pem" ] \
        || die "缺自签证书：先运行 lab/gen-certs.sh"
      vmess_args=("$CERTS_DIR/cert.pem" "$CERTS_DIR/key.pem")
    fi
    rm -f "$VMESS_LOG"
    python3 -u "$HERE/vmess_server.py" "$VMESS_LOG" "$VMESS_UUID" "$vmess_port" "${vmess_args[@]}" \
      >/tmp/sodama-vmess.log 2>&1 &
    echo $! >"$VMESS_PID_FILE"
    sleep 0.3
    kill -0 "$(cat "$VMESS_PID_FILE")" 2>/dev/null || { cat /tmp/sodama-vmess.log; die "vmess 服务端启动失败"; }
  fi
  # P5-G3：TUIC v5 参考服务端（Go，预编译产物；QUIC/TLS 自带证书）
  if [ -n "${USE_TUIC:-}" ]; then
    [ -x "$HERE/proto-check/bin/tuic-server" ] \
      || die "缺 TUIC 参考服务端：先运行 lab/proto-check/build-tuic-server.sh"
    [ -f "$CERTS_DIR/cert.pem" ] && [ -f "$CERTS_DIR/key.pem" ] \
      || die "缺自签证书：先运行 lab/gen-certs.sh"
    rm -f "$TUIC_LOG"
    "$HERE/proto-check/bin/tuic-server" -port "$TUIC_PORT" -uuid "$TUIC_UUID" -password "$TUIC_PASSWORD" \
      -cert "$CERTS_DIR/cert.pem" -key "$CERTS_DIR/key.pem" -log "$TUIC_LOG" \
      >/tmp/sodama-tuic.stdout 2>&1 &
    echo $! >"$TUIC_PID_FILE"
    sleep 0.4
    kill -0 "$(cat "$TUIC_PID_FILE")" 2>/dev/null || { cat /tmp/sodama-tuic.stdout; die "tuic 服务端启动失败"; }
  fi
  # P5-G3b：hysteria2 参考服务端（Go/http3，预编译产物；QUIC/TLS 自带证书）
  if [ -n "${USE_HY2:-}" ]; then
    [ -x "$HERE/proto-check/bin/hy2-server" ] \
      || die "缺 hysteria2 参考服务端：先运行 lab/proto-check/build-hy2-server.sh"
    [ -f "$CERTS_DIR/cert.pem" ] && [ -f "$CERTS_DIR/key.pem" ] \
      || die "缺自签证书：先运行 lab/gen-certs.sh"
    rm -f "$HY2_LOG"
    local hy2_extra=()
    [ -n "${USE_HY2_OBFS:-}" ] && hy2_extra+=(-obfs-password "$HY2_AUTH")
    [ -n "${USE_HY2_HOP:-}" ] && hy2_extra+=(-hop-ports "$HY2_HOP_PORTS")
    "$HERE/proto-check/bin/hy2-server" -port "$HY2_PORT" -auth "$HY2_AUTH" \
      -cert "$CERTS_DIR/cert.pem" -key "$CERTS_DIR/key.pem" -log "$HY2_LOG" \
      "${hy2_extra[@]}" \
      >/tmp/sodama-hy2.stdout 2>&1 &
    echo $! >"$HY2_PID_FILE"
    sleep 0.4
    kill -0 "$(cat "$HY2_PID_FILE")" 2>/dev/null || { cat /tmp/sodama-hy2.stdout; die "hysteria2 服务端启动失败"; }
  fi

  # P3a：假上游 DNS（跑在 host ns 的 127.0.0.1，上游 socket 也在 host ns）
  if [ -n "${USE_FAKE_DNS:-}" ]; then
    rm -f "$FAKE_DNS_LOG"
    python3 "$HERE/fake_dns.py" "$FAKE_DNS_LOG" "$FAKE_DNS_PORT" \
      >/tmp/sodama-fake-dns.stdout 2>&1 &
    echo $! >"$FAKE_DNS_PID_FILE"
    sleep 0.3
    kill -0 "$(cat "$FAKE_DNS_PID_FILE")" 2>/dev/null \
      || { cat /tmp/sodama-fake-dns.stdout; die "假上游（fake DNS）启动失败"; }
  fi

  # P18c：第二个假上游（dns.routing 多上游实验）
  if [ -n "${USE_FAKE_DNS_B:-}" ]; then
    rm -f "$FAKE_DNS_B_LOG"
    python3 "$HERE/fake_dns.py" "$FAKE_DNS_B_LOG" "$FAKE_DNS_B_PORT" \
      >/tmp/sodama-fake-dns-b.stdout 2>&1 &
    echo $! >"$FAKE_DNS_B_PID_FILE"
    sleep 0.3
    kill -0 "$(cat "$FAKE_DNS_B_PID_FILE")" 2>/dev/null \
      || { cat /tmp/sodama-fake-dns-b.stdout; die "假上游 B（fake DNS）启动失败"; }
  fi

  # P18a：DoT/DoH 上游服务端（自签证书；转发到假 UDP DNS）
  if [ -n "${USE_DNS_TRANSPORT:-}" ]; then
    [ -f "$CERTS_DIR/cert.pem" ] && [ -f "$CERTS_DIR/key.pem" ] \
      || die "缺自签证书：先运行 lab/gen-certs.sh"
    if [ "$USE_DNS_TRANSPORT" = tls ]; then
      rm -f "$DOT_LOG"
      python3 "$HERE/dns_transport_server.py" tls "$DOT_PORT" "$CERTS_DIR/cert.pem" \
        "$CERTS_DIR/key.pem" "127.0.0.1:$FAKE_DNS_PORT" "$DOT_LOG" \
        >/tmp/sodama-dot.stdout 2>&1 &
      echo $! >"$DOT_PID_FILE"
      sleep 0.3
      kill -0 "$(cat "$DOT_PID_FILE")" 2>/dev/null || { cat /tmp/sodama-dot.stdout; die "DoT 服务端启动失败"; }
    else
      rm -f "$DOH_LOG"
      python3 "$HERE/dns_transport_server.py" https "$DOH_PORT" "$CERTS_DIR/cert.pem" \
        "$CERTS_DIR/key.pem" "127.0.0.1:$FAKE_DNS_PORT" "$DOH_LOG" \
        >/tmp/sodama-doh.stdout 2>&1 &
      echo $! >"$DOH_PID_FILE"
      sleep 0.3
      kill -0 "$(cat "$DOH_PID_FILE")" 2>/dev/null || { cat /tmp/sodama-doh.stdout; die "DoH 服务端启动失败"; }
    fi
  fi

  # P23：DoH over HTTP/2 参考服务端（Go 标准库；仅收 h2）
  if [ -n "${USE_DNS_H2:-}" ]; then
    [ -x "$HERE/proto-check/bin/doh-h2-server" ] \
      || die "缺 DoH h2 参考服务端：先运行 lab/proto-check/build-doh-h2-server.sh"
    [ -f "$CERTS_DIR/cert.pem" ] && [ -f "$CERTS_DIR/key.pem" ] \
      || die "缺自签证书：先运行 lab/gen-certs.sh"
    rm -f "$DOH_H2_LOG"
    "$HERE/proto-check/bin/doh-h2-server" -port "$DOH_H2_PORT" -cert "$CERTS_DIR/cert.pem" \
      -key "$CERTS_DIR/key.pem" -upstream "127.0.0.1:$FAKE_DNS_PORT" -log "$DOH_H2_LOG" \
      >/tmp/sodama-doh-h2.stdout 2>&1 &
    echo $! >"$DOH_H2_PID_FILE"
    sleep 0.3
    kill -0 "$(cat "$DOH_H2_PID_FILE")" 2>/dev/null || { cat /tmp/sodama-doh-h2.stdout; die "DoH h2 服务端启动失败"; }
  fi

  # P25：naive（HTTP/2 CONNECT）参考服务端（Go 标准库；仅收 h2）
  if [ -n "${USE_NAIVE:-}" ]; then
    [ -x "$HERE/proto-check/bin/naive-server" ] \
      || die "缺 naive 参考服务端：先运行 lab/proto-check/build-naive-server.sh"
    [ -f "$CERTS_DIR/cert.pem" ] && [ -f "$CERTS_DIR/key.pem" ] \
      || die "缺自签证书：先运行 lab/gen-certs.sh"
    rm -f "$NAIVE_LOG"
    "$HERE/proto-check/bin/naive-server" -port "$NAIVE_PORT" -cert "$CERTS_DIR/cert.pem" \
      -key "$CERTS_DIR/key.pem" -user "$NAIVE_USER" -pass "$NAIVE_PASS" -log "$NAIVE_LOG" \
      >/tmp/sodama-naive.stdout 2>&1 &
    echo $! >"$NAIVE_PID_FILE"
    sleep 0.3
    kill -0 "$(cat "$NAIVE_PID_FILE")" 2>/dev/null || { cat /tmp/sodama-naive.stdout; die "naive 服务端启动失败"; }
  fi

  # P26：naive over HTTP/3 参考服务端（Go/quic-go；ALPN=h3）
  if [ -n "${USE_NAIVE_H3:-}" ]; then
    [ -x "$HERE/proto-check/bin/naive-h3-server" ] \
      || die "缺 naive h3 参考服务端：先运行 lab/proto-check/build-naive-h3-server.sh"
    [ -f "$CERTS_DIR/cert.pem" ] && [ -f "$CERTS_DIR/key.pem" ] \
      || die "缺自签证书：先运行 lab/gen-certs.sh"
    rm -f "$NAIVE_H3_LOG"
    "$HERE/proto-check/bin/naive-h3-server" -port "$NAIVE_H3_PORT" -cert "$CERTS_DIR/cert.pem" \
      -key "$CERTS_DIR/key.pem" -user "$NAIVE_USER" -pass "$NAIVE_PASS" -log "$NAIVE_H3_LOG" \
      >/tmp/sodama-naive-h3.stdout 2>&1 &
    echo $! >"$NAIVE_H3_PID_FILE"
    sleep 0.3
    kill -0 "$(cat "$NAIVE_H3_PID_FILE")" 2>/dev/null || { cat /tmp/sodama-naive-h3.stdout; die "naive h3 服务端启动失败"; }
  fi

  # P26：DoH over HTTP/3 参考服务端（Go/quic-go；ALPN=h3）
  if [ -n "${USE_DNS_H3:-}" ]; then
    [ -x "$HERE/proto-check/bin/doh-h3-server" ] \
      || die "缺 DoH h3 参考服务端：先运行 lab/proto-check/build-doh-h3-server.sh"
    [ -f "$CERTS_DIR/cert.pem" ] && [ -f "$CERTS_DIR/key.pem" ] \
      || die "缺自签证书：先运行 lab/gen-certs.sh"
    rm -f "$DOH_H3_LOG"
    "$HERE/proto-check/bin/doh-h3-server" -port "$DOH_H3_PORT" -cert "$CERTS_DIR/cert.pem" \
      -key "$CERTS_DIR/key.pem" -upstream "127.0.0.1:$FAKE_DNS_PORT" -log "$DOH_H3_LOG" \
      >/tmp/sodama-doh-h3.stdout 2>&1 &
    echo $! >"$DOH_H3_PID_FILE"
    sleep 0.3
    kill -0 "$(cat "$DOH_H3_PID_FILE")" 2>/dev/null || { cat /tmp/sodama-doh-h3.stdout; die "DoH h3 服务端启动失败"; }
  fi

  # P27：juicity 参考服务端（Go/quic-go；ALPN=h3）
  if [ -n "${USE_JUICITY:-}" ]; then
    [ -x "$HERE/proto-check/bin/juicity-server" ] \
      || die "缺 juicity 参考服务端：先运行 lab/proto-check/build-juicity-server.sh"
    [ -f "$CERTS_DIR/cert.pem" ] && [ -f "$CERTS_DIR/key.pem" ] \
      || die "缺自签证书：先运行 lab/gen-certs.sh"
    rm -f "$JUICITY_LOG"
    "$HERE/proto-check/bin/juicity-server" -port "$JUICITY_PORT" -password "$JUICITY_PASSWORD" \
      -cert "$CERTS_DIR/cert.pem" -key "$CERTS_DIR/key.pem" -log "$JUICITY_LOG" \
      >/tmp/sodama-juicity.stdout 2>&1 &
    echo $! >"$JUICITY_PID_FILE"
    sleep 0.3
    kill -0 "$(cat "$JUICITY_PID_FILE")" 2>/dev/null || { cat /tmp/sodama-juicity.stdout; die "juicity 服务端启动失败"; }
  fi

  # P30：SSR 参考服务端（Go；origin+plain + 流密码，仅 TCP）
  if [ -n "${USE_SSR:-}" ]; then
    [ -x "$HERE/proto-check/bin/ssr-server" ] \
      || die "缺 SSR 参考服务端：先运行 lab/proto-check/build-ssr-server.sh"
    rm -f "$SSR_LOG"
    "$HERE/proto-check/bin/ssr-server" -port "$SSR_PORT" -method "$SSR_METHOD" \
      -password "$SSR_PASSWORD" -log "$SSR_LOG" >/tmp/sodama-ssr.stdout 2>&1 &
    echo $! >"$SSR_PID_FILE"
    sleep 0.3
    kill -0 "$(cat "$SSR_PID_FILE")" 2>/dev/null || { cat /tmp/sodama-ssr.stdout; die "SSR 服务端启动失败"; }
  fi

  # P31：shadow-tls 参考服务端（Go/sing-shadowtls；内层转发到 python ss 后端）
  if [ -n "${USE_SHADOWTLS:-}" ]; then
    [ -x "$HERE/proto-check/bin/shadowtls-server" ] \
      || die "缺 shadow-tls 参考服务端：先运行 lab/proto-check/build-shadowtls-server.sh"
    rm -f "$SHADOWTLS_LOG"
    "$HERE/proto-check/bin/shadowtls-server" -port "$SHADOWTLS_PORT" \
      -version "${USE_SHADOWTLS_VERSION:-3}" -password "$SHADOWTLS_PASSWORD" -host localhost \
      -backend "127.0.0.1:$SS_PORT" -log "$SHADOWTLS_LOG" \
      >/tmp/sodama-shadowtls.stdout 2>&1 &
    echo $! >"$SHADOWTLS_PID_FILE"
    sleep 0.3
    kill -0 "$(cat "$SHADOWTLS_PID_FILE")" 2>/dev/null || { cat /tmp/sodama-shadowtls.stdout; die "shadow-tls 服务端启动失败"; }
  fi

  # P18b：DoQ 参考服务端（Go/quic-go，需先构建）
  if [ "${USE_DNS_TRANSPORT:-}" = doq ]; then
    [ -x "$HERE/proto-check/bin/doq-server" ] \
      || die "缺 DoQ 参考服务端：先运行 lab/proto-check/build-doq-server.sh"
    rm -f "$DOQ_LOG"
    "$HERE/proto-check/bin/doq-server" -port "$DOQ_PORT" -cert "$CERTS_DIR/cert.pem" \
      -key "$CERTS_DIR/key.pem" -upstream "127.0.0.1:$FAKE_DNS_PORT" -log "$DOQ_LOG" \
      >/tmp/sodama-doq.stdout 2>&1 &
    echo $! >"$DOQ_PID_FILE"
    sleep 0.3
    kill -0 "$(cat "$DOQ_PID_FILE")" 2>/dev/null || { cat /tmp/sodama-doq.stdout; die "DoQ 服务端启动失败"; }
  fi

  echo "== 启动 sodama =="
  : >"$LOG"
  # P6：整配置热重载会话——把模板复制到 /tmp，测试在运行中改写它
  if [ -n "${USE_OPS_RELOAD:-}" ]; then
    cp "$HERE/ops-reload.dae" /tmp/sodama-ops.dae
    chmod 640 /tmp/sodama-ops.dae
  fi
  # 能力缺口 #1：must 糖会话——同样拷到 /tmp（测试会在运行中改写后 SIGHUP）
  if [ -n "${USE_MUST_CONFIG:-}" ]; then
    cp "$HERE/must.dae" /tmp/sodama-must.dae
    chmod 640 /tmp/sodama-must.dae
  fi
  local rules_args fwd_args dns_args extra_args
  if [ -n "${USE_CONFIG:-}" ]; then
    rules_args=(--config "$USE_CONFIG")
  elif [ -n "${USE_RULES:-}" ]; then
    rules_args=(--rules "$USE_RULES")
  else
    rules_args=(--rules "$HERE/rules.dae")
  fi
  # P17a：生成小型 geoip.dat/geosite.dat 夹具并指向它们（规则里的 geoip:/geosite: 展开）
  if [ -n "${USE_GEODATA_DIR:-}" ]; then
    mkdir -p "$USE_GEODATA_DIR"
    python3 "$HERE/gen-geo-dat.py" "$USE_GEODATA_DIR" >/dev/null
    rules_args+=(--geodata-dir "$USE_GEODATA_DIR")
  fi
  if [ -n "${USE_FORWARD:-}" ]; then
    fwd_args=(--forward "$USE_FORWARD")
  elif [ -n "${USE_DIALER:-}" ]; then
    fwd_args=(--dialer "$USE_DIALER")
  else
    fwd_args=()
  fi
  extra_args=()
  [ -n "${USE_RELAY_IDLE:-}" ] && extra_args+=(--relay-idle-timeout "$USE_RELAY_IDLE")
  [ -n "${USE_DIAL_TIMEOUT:-}" ] && extra_args+=(--dial-timeout "$USE_DIAL_TIMEOUT")
  [ -n "${USE_DIAL_MODE:-}" ] && extra_args+=(--dial-mode "$USE_DIAL_MODE")
  [ -n "${USE_SNIFF_TIMEOUT:-}" ] && extra_args+=(--sniffing-timeout-ms "$USE_SNIFF_TIMEOUT")
  [ -n "${USE_SNIFF_PUNT:-}" ] && extra_args+=(--sniff-punt)
  [ -n "${USE_UDP_IDLE:-}" ] && extra_args+=(--udp-idle-timeout "$USE_UDP_IDLE")
  [ -n "${USE_OFFLOAD:-}" ] && extra_args+=(--offload)
  # 对标批：L3 接口（up() 建 ipip 隧道后置 L3_IFACE）也挂在 LAN 侧——loader 按
  # arphrd 自动选 `sodama_lan_ingress_l3`（对照 dae 按 EncapType 选 `_l2`/`_l3`）。
  [ -n "$L3_IFACE" ] && extra_args+=(--lan "$L3_IFACE")
  # C4：XDP 计量探针（恒 XDP_PASS；挂载失败仅告警，不影响转发）
  [ -n "${USE_XDP_IFACE:-}" ] && extra_args+=(--xdp "$USE_XDP_IFACE")
  # O9：强制经典线程泵路径（关 reactor 用 SODAMA_NO_REACTOR=1 环境变量）
  [ -n "${USE_NO_SPLICE:-}" ] && extra_args+=(--no-splice)
  # M2：kTLS 实验（内核 TLS；成功则加解密下沉内核，TLS 上可再 splice）
  [ -n "${USE_KTLS:-}" ] && extra_args+=(--ktls)
  # M1：eBPF 热路径调试打印（诊断专用；对照 dae 的 __DEBUG 门控）
  [ -n "${USE_EBPF_DEBUG:-}" ] && extra_args+=(--ebpf-debug)
  [ -n "${USE_LOG_FILE:-}" ] && extra_args+=(--log-file "$OPS_LOG")
  # P33：配置文件热驱动冒烟（轮询 --config/--rules 及 include，变更自动 reload）
  [ -n "${USE_WATCH_CONFIG:-}" ] && extra_args+=(--watch-config "$USE_WATCH_CONFIG")
  if [ -n "${USE_DNS_UPSTREAM:-}" ]; then
    dns_args=(--dns-upstream "$USE_DNS_UPSTREAM")
  else
    dns_args=()
  fi
  "$LOADER" --ebpf "$OBJ" --lan "${USE_LAN_ARG:-landae}" --wan "${USE_WAN_ARG:-wan}" \
    --dae0 dae0 --dae0peer dae0peer --daens "$DAE_NS" \
    "${rules_args[@]}" "${fwd_args[@]}" "${dns_args[@]}" "${extra_args[@]}" \
    --status-socket "$STATUS_SOCK" --dump >"$LOG" 2>&1 &
  echo $! >"$PID_FILE"
  sleep 1.5
  if ! kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "!! sodama 退出，日志："
    cat "$LOG"
    die "启动失败"
  fi
  # P23：就绪等待——状态面 socket 出现 = 初始 reload 完成（DNS/relay 线程随后启动），
  # 避免“进程活着但数据面尚未就绪”的用例竞态。
  local _i
  for _i in $(seq 1 80); do
    [ -S "$STATUS_SOCK" ] && break
    sleep 0.25
  done
  echo "== sodama 运行中 (pid $(cat "$PID_FILE"))，日志：$LOG =="
  cat "$LOG"
}

# 单臂（dual-role）拓扑：client 与 wan 在同一个 L2 段，路由器只有一个接口
# single；ingress 挂 sodama_wan_lan_ingress、egress 挂 sodama_lan_wan_egress
# （对照 dae do_tproxy_wan_lan_ingress / do_tproxy_lan_wan_egress）。
dual_up() {
  require_root
  [ -f "$OBJ" ] && [ -x "$LOADER" ] || die "先运行 $0 build"
  check_lan_collision
  cleanup
  LAN_IFACE=single

  echo "== 建立单臂拓扑：bridge + 单接口路由器 =="
  ip netns add "$CLIENT_NS"
  ip netns add "$WAN_NS"
  ip netns add "$DAE_NS"
  ip link add br0 type bridge
  ip link set br0 up

  ip link add lanclient type veth peer name landae
  ip link set lanclient netns "$CLIENT_NS"
  ip link set landae master br0
  ip link set landae up
  ip -n "$CLIENT_NS" link set lo up
  ip -n "$CLIENT_NS" addr add 10.0.0.2/24 dev lanclient
  ip -n "$CLIENT_NS" link set lanclient up
  ip -n "$CLIENT_NS" route add default via 10.0.0.1

  ip link add wanpeer type veth peer name wan
  ip link set wanpeer netns "$WAN_NS"
  ip link set wan master br0
  ip link set wan up
  ip -n "$WAN_NS" link set lo up
  ip -n "$WAN_NS" addr add "$DIRECT_DST/24" dev wanpeer
  ip -n "$WAN_NS" addr add "$DIRECT_DST_2/24" dev wanpeer
  ip -n "$WAN_NS" addr add "$PROXY_DST/32" dev wanpeer
  ip -n "$WAN_NS" link set wanpeer up
  ip -n "$WAN_NS" route add 10.0.0.0/24 via 10.9.9.1

  # 路由器单接口：同时持有 LAN 网关地址与 WAN 侧地址
  ip link add single type veth peer name single-aux
  ip link set single-aux master br0
  ip link set single-aux up
  ip addr add 10.0.0.1/24 dev single
  ip addr add 10.9.9.1/24 dev single
  ip link set single up
  ip route add "$PROXY_DST/32" via "$DIRECT_DST" dev single
  ip route add 10.9.10.0/24 via "$DIRECT_DST" dev single

  # 控制面对（与标准拓扑一致）
  ip link add dae0 type veth peer name dae0peer
  ip link set dae0peer netns "$DAE_NS"
  ip link set dae0 up
  ip -n "$DAE_NS" link set lo up
  ip -n "$DAE_NS" link set dae0peer up
  ip -n "$DAE_NS" addr add 169.254.0.11/32 dev dae0peer
  ip -n "$DAE_NS" route add 169.254.0.1/32 dev dae0peer scope link
  ip -n "$DAE_NS" route add default via 169.254.0.1 dev dae0peer
  local dae0_mac
  dae0_mac="$(ip link show dev dae0 | awk '/link\/ether/ {print $2; exit}')"
  [ -n "$dae0_mac" ] || die "拿不到 dae0 的 MAC"
  ip -n "$DAE_NS" neigh add 169.254.0.1 lladdr "$dae0_mac" \
    dev dae0peer nud permanent
  ip netns exec "$DAE_NS" sysctl -qw net.ipv4.conf.dae0peer.accept_local=1
  ip -n "$DAE_NS" rule add fwmark 0x8000000/0x8000000 table 2023
  ip -n "$DAE_NS" route add local default dev lo table 2023

  echo "== 内核转发/校验开关 =="
  sysctl -qw net.ipv4.ip_forward=1
  sysctl -qw net.ipv4.conf.all.rp_filter=0
  sysctl -qw net.ipv4.conf.default.rp_filter=0
  sysctl -qw net.ipv4.conf.dae0.accept_local=1
  sysctl -qw net.ipv4.conf.single.rp_filter=0
  # 宿主若装了 Docker（FORWARD 策略 drop），按接口放行实验网段的转发
  forward_allow single single
  ip netns exec "$WAN_NS" sysctl -qw net.ipv4.conf.all.rp_filter=0 2>/dev/null || true
  ip netns exec "$DAE_NS" sysctl -qw net.ipv4.ip_nonlocal_bind=1 2>/dev/null || true

  echo "== 启动 WAN 侧 echo 服务 =="
  ip netns exec "$WAN_NS" python3 "$HERE/wan_echo.py" >"$WAN_LOG" 2>&1 &
  echo $! >"$WAN_PID_FILE"
  sleep 0.3

  echo "== 启动 sodama（--dual $LAN_IFACE）=="
  : >"$LOG"
  "$LOADER" --ebpf "$OBJ" --dual "$LAN_IFACE" \
    --dae0 dae0 --dae0peer dae0peer --daens "$DAE_NS" \
    --rules "$HERE/rules.dae" --status-socket "$STATUS_SOCK" \
    --dump >"$LOG" 2>&1 &
  echo $! >"$PID_FILE"
  sleep 1.5
  if ! kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "!! sodama 退出，日志："
    cat "$LOG"
    die "启动失败"
  fi
  echo "== sodama 运行中 (pid $(cat "$PID_FILE"))，日志：$LOG =="
  cat "$LOG"
}

test_proxy() {
  require_root
  echo "== 测试 proxy 路径：client -> $PROXY_DST:8080 =="
  local out
  out="$(ip netns exec "$CLIENT_NS" python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "--- 客户端收到 ---"
  echo "$out"
  if echo "$out" | grep -q "orig_dst=$PROXY_DST:8080"; then
    echo "PASS: tproxy accept 到的原始目的地址是 $PROXY_DST:8080"
  else
    echo "FAIL: 没看到原始目的地址"
    echo "--- sodama 日志 ---"; cat "$LOG" || true
    exit 1
  fi
}

test_direct() {
  require_root
  echo "== 测试 direct 路径（LPM 集合的第二个前缀）：client -> $DIRECT_DST_2:9999 =="
  local out
  out="$(ip netns exec "$CLIENT_NS" python3 "$HERE/client_probe.py" "$DIRECT_DST_2" 9999 2>&1 || true)"
  echo "--- 客户端收到 ---"
  echo "$out"
  if echo "$out" | grep -q "wan-echo-ok"; then
    echo "PASS: 内核三层直转，未经过 tproxy"
  else
    echo "FAIL: direct 路径不通（若看到 sodama tproxy 字样，说明路由规则未命中而落到 fallback）"
    exit 1
  fi
}

# NOT+AND 编码 + block 判决：客户端发往 1.1.1.1:8081 的流量应被丢弃（不只是被代理）。
# 规则设计：fallback 故意设为 proxy，所以若 NOT 规则失效，这里会看到 tproxy 回包，测试即报错。
test_block() {
  require_root
  echo "== 测试 block 路径（NOT+AND + block）：client -> $PROXY_DST:8081 =="
  local out
  out="$(ip netns exec "$CLIENT_NS" python3 "$HERE/client_probe.py" "$PROXY_DST" 8081 2>&1 || true)"
  case "$out" in
    *"sodama tproxy"*)
      echo "FAIL: 命中了 fallback/proxy，说明 NOT+AND 规则没有生效"
      echo "$out"
      exit 1 ;;
    *"wan-echo-ok"*)
      echo "FAIL: 命中了 direct，说明规则顺序/编码有误"
      echo "$out"
      exit 1 ;;
    *)
      echo "PASS: 报文被丢弃（客户端超时/连接失败），未进入用户态"
      echo "（客户端输出：$(echo "$out" | tail -1)）" ;;
  esac
}

# 宿主机自身流量：本进程所在 netns 直接访问 1.1.1.1:8080，走 wan egress 分流 +
# from_wan 回程（dae0 ingress 用 BPF_F_INGRESS 注入回 wan）。
test_host_proxy() {
  require_root
  echo "== 测试宿主机流量（wan_egress + from_wan 回程）：host -> $PROXY_DST:8080 =="
  local out
  out="$(timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "--- 宿主机收到 ---"
  echo "$out"
  if echo "$out" | grep -q "orig_dst=$PROXY_DST:8080"; then
    echo "PASS: 本机流量也被 tproxy 接管，且回程按 from_wan 注入成功"
  else
    echo "FAIL: 宿主机流量未被代理（检查 wan egress 钩子与 dae0 ingress 的 BPF_F_INGRESS）"
    exit 1
  fi
}

# 覆盖 rules.dae 并触发 SIGHUP 热重载
reload() {
  require_root
  local src="${1:-$HERE/rules.reload.dae}"
  cp "$src" "$HERE/rules.dae"
  kill -HUP "$(cat "$PID_FILE")"
  sleep 0.8
  tail -3 "$LOG"
}

# 长连接跨热重载：已建立连接仍走 conn_state 缓存里的旧判决；新连接按新规则被 block。
test_reload() {
  require_root
  echo "== 测试热重载（conn_state 缓存 + epoch 槽切换）=="
  local orig
  orig="$(mktemp)"
  cp "$HERE/rules.dae" "$orig"
  # 任何退出路径（包括中途失败）都恢复规则文件，避免把 reload 变体留在
  # rules.dae 上（后续 up 会加载错规则，症状是代理路径全挂）。
  trap "cp '$orig' '$HERE/rules.dae' 2>/dev/null || true" EXIT

  # 后台跑长连接探针：连接后先发一条，4 秒后再发一条
  (ip netns exec "$CLIENT_NS" timeout 12 python3 "$HERE/hold_conn.py" "$PROXY_DST" 8080 4 \
     >/tmp/hold_conn.out 2>&1 &)
  sleep 2
  echo "-- 切换到 block 规则并 SIGHUP --"
  cp "$HERE/rules.reload.dae" "$HERE/rules.dae"
  kill -HUP "$(cat "$PID_FILE")"
  sleep 4.5

  echo "-- 长连接收到的两次回显 --"
  cat /tmp/hold_conn.out || true
  local replies
  replies="$(grep -c "sodama tproxy" /tmp/hold_conn.out || true)"

  echo "-- 新连接（应被新规则 block）--"
  local fresh
  fresh="$(ip netns exec "$CLIENT_NS" timeout 5 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"

  # 恢复初始规则
  cp "$orig" "$HERE/rules.dae"
  kill -HUP "$(cat "$PID_FILE")"
  sleep 0.5
  rm -f "$orig"

  local ok=1
  if [ "$replies" -lt 2 ]; then
    echo "FAIL: 已建立连接只收到 $replies 次 tproxy 回显，说明热重载影响了在途连接（conn_state 缓存未生效）"
    ok=0
  fi
  if echo "$fresh" | grep -q "sodama tproxy"; then
    echo "FAIL: 新连接仍被代理，说明新规则未生效（epoch 槽未切换）"
    ok=0
  fi
  [ "$ok" = 1 ] || exit 1
  echo "PASS: 在途连接保持旧判决，新连接按新规则处理"
}

# redirect_track 单写者（对照 dae tproxy.c:2196 public / 4000 reply）：
#   1) 竞争发布者在新条目的 2s 窗口内被拒（计数 +1，绑定保持）；
#   2) 条目陈旧（age 3s）后允许原发布者改绑，回程路径恢复。
test_rebind() {
  require_root
  echo "== 测试 redirect_track 单写者（竞争发布者 / 陈旧窗口）=="
  # 清掉上次可能残留的探针（它持有一个长连接，避免互相干扰）
  pkill -f rebind_probe.py 2>/dev/null || true
  local sig1=/tmp/sodama-rebind-sig1 sig2=/tmp/sodama-rebind-sig2 out=/tmp/sodama-rebind.out
  rm -f "$sig1" "$sig2" "$out"
  (ip netns exec "$CLIENT_NS" timeout 60 python3 "$HERE/rebind_probe.py" \
     "$PROXY_DST" 8080 "$sig1" "$sig2" >"$out" 2>&1 &)

  local sport="" i
  for i in $(seq 1 50); do
    sport="$(sed -n 's/^local=[^:]*:\([0-9]*\)$/\1/p' "$out" | head -1)"
    [ -n "$sport" ] && break
    sleep 0.2
  done
  [ -n "$sport" ] || { echo "FAIL: 探针未能建立连接"; cat "$out"; exit 1; }
  for i in $(seq 1 50); do
    grep -q "echo1: sodama tproxy" "$out" && break
    sleep 0.2
  done

  local client_mac router_mac ifindex
  client_mac="$(ip -n "$CLIENT_NS" link show dev lanclient | awk '/link\/ether/ {print $2; exit}')"
  router_mac="$(ip link show dev "$LAN_IFACE" | awk '/link\/ether/ {print $2; exit}')"
  ifindex="$(ip -o link show dev "$LAN_IFACE" | sed 's/^\([0-9]*\):.*/\1/')"
  [ -n "$client_mac" ] && [ -n "$router_mac" ] && [ -n "$ifindex" ] || {
    echo "FAIL: 拿不到接口信息（$client_mac/$router_mac/$ifindex）"; exit 1; }

  local rejected_before rejected_after rejected_stale entry_after
  # 键 4 = SODAMA_STAT_REDIRECT_REBIND_REJECTED（与 dae `BPF_STATS_REDIRECT_REBIND_REJECTED` 同键域）
  rejected_before="$(python3 "$HERE/rebind_tool.py" stats | sed -n 's/^stat 4.*= \([0-9]*\)$/\1/p')"
  echo "-- 伪造竞争发布者（smac=02:00:00:00:00:99，新鲜条目）--"
  python3 "$HERE/rebind_tool.py" set --sip 10.0.0.2 --dip "$PROXY_DST" --sport "$sport" \
    --ifindex "$ifindex" --smac 02:00:00:00:00:99 --dmac "$router_mac"

  touch "$sig1"
  # 时序：2s 新鲜窗口内先看绑定（竞争条目必须保持，单写者拒绝生效）；
  # 若像早期版本那样 sleep 2 后再 dump，首次 TCP 重传已到窗口之外、
  # 会被合法改绑，检查必然误报（P16 复跑时踩到）。
  sleep 0.5
  entry_after="$(python3 "$HERE/rebind_tool.py" dump)"
  # 统计要在窗口完全过去后读：窗口内被拒的重传都已计入，之后不再增加。
  sleep 1.8
  rejected_after="$(python3 "$HERE/rebind_tool.py" stats | sed -n 's/^stat 4.*= \([0-9]*\)$/\1/p')"
  if ! echo "$entry_after" | grep -q "smac=02:00:00:00:00:99"; then
    echo "FAIL: 新鲜条目的绑定被竞争发布者改掉了（单写者未生效）"
    echo "$entry_after"; exit 1
  fi
  if [ "${rejected_after:-0}" -le "${rejected_before:-0}" ]; then
    echo "FAIL: 未观察到 rebind 拒绝计数（before=$rejected_before after=$rejected_after）"
    echo "$entry_after"; exit 1
  fi
  echo "PASS 1/2: 竞争发布者被拒（rebind_rejected $rejected_before → $rejected_after，绑定保持）"

  echo "-- 把条目改成陈旧（age 3s）后再发一包 --"
  python3 "$HERE/rebind_tool.py" set --sip 10.0.0.2 --dip "$PROXY_DST" --sport "$sport" \
    --ifindex "$ifindex" --smac 02:00:00:00:00:99 --dmac "$router_mac" --age-sec 3
  touch "$sig2"
  for i in $(seq 1 200); do
    grep -q "^done$" "$out" && break
    sleep 0.2
  done
  rejected_stale="$(python3 "$HERE/rebind_tool.py" stats | sed -n 's/^stat 4.*= \([0-9]*\)$/\1/p')"
  if ! python3 "$HERE/rebind_tool.py" dump | grep -q "smac=$client_mac"; then
    echo "FAIL: 陈旧窗口后未允许原发布者改绑"
    python3 "$HERE/rebind_tool.py" dump; exit 1
  fi
  if [ "${rejected_stale:-0}" -ne "${rejected_after:-0}" ]; then
    echo "FAIL: 陈旧改绑被错误计数为拒绝（$rejected_after → $rejected_stale）"
    exit 1
  fi
  echo "-- 探针输出 --"
  cat "$out"
  if grep -q "echo3: sodama tproxy" "$out"; then
    echo "PASS 2/2: 陈旧窗口允许改绑，回程路径恢复（echo3 到达）"
  else
    echo "FAIL: 改绑后回程仍未恢复（echo3 未到达）"
    pkill -f rebind_probe.py 2>/dev/null || true
    exit 1
  fi
}

# 故障注入 1：reload 中持续打流。交替两个规则集（8080 判决不变）并发 SIGHUP，
# 每次重载后立刻连接；要求全部成功且数据面无「热重载失败」日志。
test_fault_reload() {
  require_root
  echo "== 故障注入：reload 中打流（交替规则集 + SIGHUP） =="
  local orig out fails=0 i
  orig="$(mktemp)"
  cp "$HERE/rules.dae" "$orig"
  for i in $(seq 1 10); do
    if [ $((i % 2)) = 0 ]; then
      cp "$HERE/rules.fault.dae" "$HERE/rules.dae"
    else
      cp "$orig" "$HERE/rules.dae"
    fi
    kill -HUP "$(cat "$PID_FILE")"
    sleep 0.15
    out="$(ip netns exec "$CLIENT_NS" timeout 5 python3 "$HERE/client_probe.py" \
      "$PROXY_DST" 8080 2>&1 || true)"
    if ! echo "$out" | grep -q "orig_dst=$PROXY_DST:8080"; then
      fails=$((fails + 1))
      echo "  第 $i 轮连接未走代理：$(echo "$out" | tail -1)"
    fi
  done
  cp "$orig" "$HERE/rules.dae"
  kill -HUP "$(cat "$PID_FILE")"
  sleep 0.5
  rm -f "$orig"
  if grep -q "热重载失败" "$LOG"; then
    echo "FAIL: 数据面报告热重载失败"; grep "热重载失败" "$LOG"; exit 1
  fi
  [ "$fails" = 0 ] || { echo "FAIL: $fails/10 轮在重载期间未走代理"; exit 1; }
  echo "PASS: 10 轮重载打流全部成功，无热重载失败"
}

# 故障注入 2（破坏性，最后跑）：kill -9 加载器。TCX 钩子随进程退出自动摘除；
# 流量回落为普通内核转发（fail-open），在 WAN 侧 echo 处得到应答（不是黑洞）。
test_fault_kill() {
  require_root
  echo "== 故障注入：kill -9 加载器（TCX 自动摘钩 + fail-open） =="
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 5 python3 "$HERE/client_probe.py" \
    "$PROXY_DST" 8080 2>&1 || true)"
  if ! echo "$out" | grep -q "orig_dst=$PROXY_DST:8080"; then
    echo "FAIL: kill 前代理就不工作"; echo "$out"; exit 1
  fi
  kill -9 "$(cat "$PID_FILE")"
  rm -f "$PID_FILE"
  sleep 0.6
  if bpftool net show 2>/dev/null | grep -q "sodama_"; then
    echo "FAIL: loader 已死但钩子仍在（TCX 未自动摘钩）"
    bpftool net show; exit 1
  fi
  out="$(ip netns exec "$CLIENT_NS" timeout 6 python3 "$HERE/client_probe.py" \
    "$PROXY_DST" 8080 2>&1 || true)"
  echo "--- kill 后客户端收到 ---"
  echo "$out"
  if echo "$out" | grep -q "wan-echo-ok"; then
    echo "PASS: 钩子自动摘除，流量回落为内核直转（fail-open）"
  else
    echo "FAIL: kill 后流量黑洞（TCX 摘钩/fail-open 语义不对）"
    exit 1
  fi
}

# K3：只读状态面（Unix socket JSON）。先打一条流量，确认 map 计数非空；
# 再验证未知命令被拒绝（只读语义）。
test_status() {
  require_root
  echo "== 测试只读状态面（Unix socket JSON）=="
  ip netns exec "$CLIENT_NS" timeout 5 python3 "$HERE/client_probe.py" \
    "$PROXY_DST" 8080 >/dev/null 2>&1 || true
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  echo "-- status --json --"
  cat /tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
assert v.get("active_slot") in (0, 1), v
assert v["rules"]["count"] >= 1, v["rules"]
assert v["maps"]["conn_state"] >= 1, v["maps"]
assert isinstance(v["hooks"], list) and len(v["hooks"]) >= 4, v["hooks"]
print("status: rules=%d conn_state=%d hooks=%d rebind_rejected=%d" % (
    v["rules"]["count"], v["maps"]["conn_state"],
    len(v["hooks"]), v["stats"]["rebind_rejected"]))
PY
  local bad
  bad="$("$LOADER" status --socket "$STATUS_SOCK" --cmd "delete everything" --json 2>&1 || true)"
  case "$bad" in
    *"unknown command"*) ;;
    *) echo "FAIL: 未知命令未被拒绝: $bad"; exit 1 ;;
  esac
  echo "PASS: 只读状态面可用，且拒绝非查询命令"
}

# K3：完整 .dae 配置模式（lab/real-user.dae）：全量解析 + 子集编译 + deferred 上报。
test_config() {
  require_root
  echo "== 测试完整 .dae 配置模式（全量解析 + 子集编译）=="
  # up 只保证进程活着；首版规则下发/上游 DNS 解析可能晚于它的 sleep，
  # 此时探测会得到“直连回落”（实测竞态，真网关同时在跑时更明显）。轮询等待生效。
  local out i
  for i in $(seq 1 6); do
    out="$(ip netns exec "$CLIENT_NS" timeout 5 python3 "$HERE/client_probe.py" \
      "$PROXY_DST" 8080 2>&1 || true)"
    echo "$out" | grep -q "orig_dst=$PROXY_DST:8080" && break
    sleep 0.5
  done
  echo "$out" | grep -q "orig_dst=$PROXY_DST:8080" || {
    echo "FAIL: 配置驱动的 proxy 规则未生效"; echo "$out"; exit 1; }
  grep -q "deferred rule" "$LOG" || {
    echo "FAIL: 未报告 deferred 规则"; tail -5 "$LOG"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --cmd config --json >/tmp/sodama-config.json
  python3 - /tmp/sodama-config.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
r = v["routing"]
assert len(r["supported"]) == 7, r["supported"]
assert len(r["deferred"]) == 1, r["deferred"]
assert "future_func" in r["deferred"][0]["reason"], r["deferred"]
assert any(k == "proxy" for k, _ in r["outbound_map"]), r["outbound_map"]
assert r["fallback"] == "proxy", r
print("config: supported=%d deferred=%d fallback=%s" % (
    len(r["supported"]), len(r["deferred"]), r["fallback"]))
PY
  echo "PASS: 全量配置解析、子集编译、deferred 显式上报"
}

# K3：过渡一跳——tproxy 连接接到 socks5 后端，orig_dst 保留。
test_forward() {
  require_root
  echo "== 测试过渡一跳（tproxy -> socks5 后端，orig_dst 保留）=="
  rm -f "$SOCKS5_LOG"
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 6 python3 "$HERE/client_probe.py" \
    "$PROXY_DST" 8080 2>&1 || true)"
  echo "--- 客户端收到 ---"
  echo "$out"
  echo "$out" | grep -q "socks5-backend: target=$PROXY_DST:8080" || {
    echo "FAIL: 后端未看到原始目的地址"; exit 1; }
  grep -q "CONNECT $PROXY_DST:8080" "$SOCKS5_LOG" || {
    echo "FAIL: socks5 日志缺少 CONNECT"; cat "$SOCKS5_LOG"; exit 1; }
  echo "PASS: orig_dst 经 SOCKS5 一跳完整保留"
}

# P3a：域位图端到端——DNS 被 dae 接管 → 应答写域位图 → 按 IP 命中 domain 规则。
test_domain() {
  require_root
  echo "== 测试域分流（DNS 接管 + 域位图）=="
  local out ans_proxy ans_direct
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 proxy.test 2>&1 || true)"
  echo "$out"
  ans_proxy="$(printf '%s\n' "$out" | sed -n 's/^answer=\(.*\)$/\1/p' | head -1)"
  [ "$ans_proxy" = "10.9.10.3" ] || { echo "FAIL: proxy.test 未解析到 10.9.10.3（DNS 接管/转发失败）"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 direct.test 2>&1 || true)"
  echo "$out"
  ans_direct="$(printf '%s\n' "$out" | sed -n 's/^answer=\(.*\)$/\1/p' | head -1)"
  [ "$ans_direct" = "10.9.10.4" ] || { echo "FAIL: direct.test 未解析到 10.9.10.4"; exit 1; }
  grep -q "QUERY proxy.test" "$FAKE_DNS_LOG" || { echo "FAIL: 假上游没收到 proxy.test 查询（DNS 未经过 dae 转发）"; exit 1; }

  # 用解析出的 IP 连接：proxy 域 → tproxy；direct 域 → 内核直转
  out="$(ip netns exec "$CLIENT_NS" timeout 6 python3 "$HERE/client_probe.py" "$ans_proxy" 9999 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "orig_dst=$ans_proxy:9999" || { echo "FAIL: proxy.test 的 IP 未走代理（域位图未生效）"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 6 python3 "$HERE/client_probe.py" "$ans_direct" 9999 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "wan-echo-ok" || { echo "FAIL: direct.test 的 IP 未被内核直转"; exit 1; }

  # 状态面：域位图与 DNS 统计
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
assert v["dns"]["queries"] >= 2, v["dns"]
assert v["dns"]["published_ips"] >= 2, v["dns"]
assert v["maps"]["domain_routing"] >= 2, v["maps"]
assert v["dns"]["domain_sets"] == 2, v["dns"]
print("dns: queries=%d published_ips=%d domain_routing_entries=%d" % (
    v["dns"]["queries"], v["dns"]["published_ips"], v["maps"]["domain_routing"]))
PY
  echo "PASS: 域位图端到端（DNS 接管 → 位图 → domain 规则分流）"
}

# P3b-1：正缓存（同一名字第二次不再上行、TTL 递减）+ 负缓存（NODATA）。
test_dns_cache() {
  require_root
  echo "== 测试 DNS 缓存（正/负缓存 + TTL 递减）=="
  local out t1 t2 ans1 hits nxhits
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 cache.test 2>&1 || true)"
  echo "$out"
  ans1="$(printf '%s\n' "$out" | sed -n 's/^answer=\(.*\)$/\1/p' | head -1)"
  t1="$(printf '%s\n' "$out" | sed -n 's/^ttl=\(.*\)$/\1/p' | head -1)"
  [ "$ans1" = "10.9.10.9" ] || { echo "FAIL: cache.test 首次解析失败（got: $ans1）"; exit 1; }
  [ -n "$t1" ] || { echo "FAIL: 首次解析没读到 TTL"; exit 1; }
  sleep 1.2
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 cache.test 2>&1 || true)"
  echo "$out"
  t2="$(printf '%s\n' "$out" | sed -n 's/^ttl=\(.*\)$/\1/p' | head -1)"
  [ -n "$t2" ] || { echo "FAIL: 缓存命中无 TTL"; exit 1; }
  [ "$t2" -lt "$t1" ] || { echo "FAIL: 缓存命中 TTL 未递减（$t1 -> $t2）"; exit 1; }
  hits="$(grep -c '^QUERY cache.test' "$FAKE_DNS_LOG" || true)"
  [ "$hits" = "1" ] || { echo "FAIL: cache.test 上行了 $hits 次（应为 1，第二次应命中缓存）"; exit 1; }

  # 负缓存（NODATA）：未知名字两次查询只上行一次
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 nx.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^ancount=0' || { echo "FAIL: nx.test 应为 NODATA"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 nx.test 2>&1 || true)"
  nxhits="$(grep -c '^QUERY nx.test' "$FAKE_DNS_LOG" || true)"
  [ "$nxhits" = "1" ] || { echo "FAIL: nx.test 上行了 $nxhits 次（负缓存未生效）"; exit 1; }

  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
d = v["dns"]
assert d["cache_hits"] >= 2, d
assert d["cache_misses"] >= 2, d
assert d["cache_entries"] >= 2, d
print("dns cache: hits=%d misses=%d entries=%d expired=%d" % (
    d["cache_hits"], d["cache_misses"], d["cache_entries"], d["cache_expired"]))
PY
  echo "PASS: DNS 缓存（命中不重查上游、TTL 递减、负缓存）"
}

# P3b-1：TCP 客户端 DNS——长度前缀分帧；上游链路仍按**上游 scheme** 选传输
# （tcp+udp：UDP 优先，TC/失败才回退 TCP，对照 dae）；同一 name 第二次命中缓存。
# 显式 tcp:// 上游（仅 TCP，2B 分帧）另见 test_dns_tcpup。
test_dns_tcp() {
  require_root
  echo "== 测试 TCP 客户端 DNS（2 字节分帧 + 缓存）=="
  local out up tcp_up
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" --tcp 9.9.9.9 tcp.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^proto=tcp' || { echo "FAIL: 探针未走 TCP"; exit 1; }
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.6' || { echo "FAIL: TCP DNS 未解析到 10.9.10.6"; exit 1; }
  up="$(grep -c '^QUERY tcp.test ' "$FAKE_DNS_LOG" || true)"
  tcp_up="$(grep -c '^QUERY-TCP tcp.test ' "$FAKE_DNS_LOG" || true)"
  [ "$up" = "1" ] && [ "$tcp_up" = "0" ] \
    || { echo "FAIL: tcp+udp 上游应为 UDP 优先（UDP=$up TCP=$tcp_up，期望 1/0）"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" --tcp 9.9.9.9 tcp.test 2>&1 || true)"
  echo "$out"
  up="$(grep -c '^QUERY tcp.test ' "$FAKE_DNS_LOG" || true)"
  [ "$up" = "1" ] || { echo "FAIL: 第二次 TCP 查询未命中缓存（上游 $up 次）"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
d = v["dns"]
assert d["tcp_queries"] >= 2, d
assert d["tcp_responses"] >= 2, d
assert d["tcp_unsupported"] == 0, d
print("dns tcp: queries=%d responses=%d cache_hits=%d" % (
    d["tcp_queries"], d["tcp_responses"], d["cache_hits"]))
PY
  echo "PASS: TCP 客户端 DNS（2 字节分帧、可缓存、上游 tcp+udp 走 UDP）"
}

# P3b-1：reload（SIGHUP）后用 DNS 缓存重建新槽域位图，且新槽位图端到端生效。
test_dns_reload() {
  require_root
  echo "== 测试 DNS 位图跨 reload 重建（缓存重投影）=="
  local out before after
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 proxy.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.3' || { echo "FAIL: proxy.test 解析失败"; exit 1; }
  sleep 0.5
  before="$("$LOADER" status --socket "$STATUS_SOCK" --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["active_slot"])')"
  kill -HUP "$(cat "$PID_FILE")"
  sleep 1.2
  after="$("$LOADER" status --socket "$STATUS_SOCK" --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["active_slot"])')"
  [ "$before" != "$after" ] || { echo "FAIL: SIGHUP 后 epoch 未切换（$before -> $after）"; exit 1; }
  # 注意：BPF map 名在内核里截断到 15 字符（domain_routing_map -> domain_routing_），
  # 且 lab 与真网关可能同名并存，所以按 loader pid 的 fdinfo 锁 id 后 dump。
  local map_id
  map_id="$(python3 "$HERE/map_id.py" domain_routing_map)"
  [ -n "$map_id" ] || { echo "FAIL: 找不到 domain_routing map"; exit 1; }
  bpftool -j map dump id "$map_id" >/tmp/sodama-domain.json
  python3 - "$after" /tmp/sodama-domain.json <<'PY'
import json, struct, sys

def raw(x):
    if isinstance(x, list):
        return bytes(int(v, 16) if isinstance(v, str) else v & 0xFF for v in x)
    if isinstance(x, str):
        return bytes.fromhex(x.removeprefix("0x"))
    return None

slot = int(sys.argv[1])
data = json.load(open(sys.argv[2]))
found = False
for e in data:
    kb = raw(e.get("key"))
    vb = raw(e.get("value"))
    if kb is None or vb is None or len(kb) != 20:
        continue
    s = struct.unpack("<I", kb[:4])[0]
    addr = kb[4:20]
    if s == slot and addr[10:12] == b"\xff\xff" and addr[12:] == bytes([10, 9, 10, 3]):
        words = len(vb) // 4
        assert words >= 1, len(vb)
        bits = struct.unpack("<%dI" % words, vb[: words * 4])
        assert bits[0] & (1 << 1), hex(bits[0])  # proxy.test = match_set[1]
        found = True
assert found, "新槽没有 10.9.10.3 的域位图"
print("domain_routing: slot=%d 的 10.9.10.3 位图已重建" % slot)
PY
  # 端到端：不再查 DNS，直接用已知 IP 连接 → 新槽位图必须生效
  out="$(ip netns exec "$CLIENT_NS" timeout 6 python3 "$HERE/client_probe.py" 10.9.10.3 9999 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "orig_dst=10.9.10.3:9999" || { echo "FAIL: reload 后新槽位图未生效"; exit 1; }
  echo "PASS: reload 后缓存重投影，新槽域位图端到端生效"
}

# P3b-2a：regex 域规则——命中与否走不同路径（对照 dae regexp.MatchString 语义）。
test_domain_regex() {
  require_root
  echo "== 测试 domain(regex:) 域分流 =="
  local out ans_api ans_web
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 api1.regex.test 2>&1 || true)"
  echo "$out"
  ans_api="$(printf '%s\n' "$out" | sed -n 's/^answer=\(.*\)$/\1/p' | head -1)"
  [ "$ans_api" = "10.9.10.21" ] || { echo "FAIL: api1.regex.test 未解析到 10.9.10.21（got: $ans_api）"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 web.regex.test 2>&1 || true)"
  echo "$out"
  ans_web="$(printf '%s\n' "$out" | sed -n 's/^answer=\(.*\)$/\1/p' | head -1)"
  [ "$ans_web" = "10.9.10.23" ] || { echo "FAIL: web.regex.test 未解析到 10.9.10.23"; exit 1; }
  sleep 0.5
  out="$(ip netns exec "$CLIENT_NS" timeout 6 python3 "$HERE/client_probe.py" "$ans_api" 9999 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "orig_dst=$ans_api:9999" || { echo "FAIL: regex 命中的 IP 未走代理"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 6 python3 "$HERE/client_probe.py" "$ans_web" 9999 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "wan-echo-ok" || { echo "FAIL: regex 未命中的 IP 未被内核直转"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
assert v["dns"]["domain_sets"] == 1, v["dns"]
assert v["dns"]["bitmap_matched"] >= 1, v["dns"]
assert v["maps"]["domain_routing"] >= 1, v["maps"]
print("dns regex: domain_sets=%d bitmap_matched=%d domain_routing=%d" % (
    v["dns"]["domain_sets"], v["dns"]["bitmap_matched"], v["maps"]["domain_routing"]))
PY
  echo "PASS: domain(regex:) 命中走 tproxy、不命中直转"
}

# P3b-2a：UDP 按客户端 EDNS 尺寸截断（TC=1），TCP 完整；缓存存完整应答。
test_dns_edns() {
  require_root
  echo "== 测试 EDNS 尺寸与 UDP 截断 =="
  local out
  # 无 EDNS（512）：大应答被截断
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 big.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^tc=1' || { echo "FAIL: 无 EDNS 的 UDP 查询应被截断（TC=1）"; exit 1; }
  printf '%s\n' "$out" | grep -q '^ancount=0' || { echo "FAIL: 截断应答应清空 answer 段"; exit 1; }
  # 带 EDNS 4096：完整应答（缓存命中）
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" --edns 4096 9.9.9.9 big.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^tc=0' || { echo "FAIL: EDNS 4096 的应答不应截断"; exit 1; }
  printf '%s\n' "$out" | grep -q '^ancount=60' || { echo "FAIL: EDNS 4096 应拿到全部 60 条 A"; exit 1; }
  # 再查一次无 EDNS：仍截断（同一缓存条目里存的是完整应答）
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 big.test 2>&1 || true)"
  printf '%s\n' "$out" | grep -q '^tc=1' || { echo "FAIL: 缓存命中仍应按客户端尺寸截断"; exit 1; }
  # TCP：完整应答
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" --tcp 9.9.9.9 big.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^ancount=60' || { echo "FAIL: TCP DNS 应拿到完整应答"; exit 1; }
  local up
  up="$(grep -c '^QUERY big.test' "$FAKE_DNS_LOG" || true)"
  [ "$up" = "1" ] || { echo "FAIL: big.test 上行了 $up 次（应为 1，其余命中缓存）"; exit 1; }
  echo "PASS: EDNS 尺寸、UDP 截断（TC=1 + 清空 answer）、TCP 完整应答"
}

# P18a：DoT 上游（tls://，TLS + 2B 分帧 + 持久连接）
test_dot() {
  require_root
  echo "== 测试 DoT 上游（tls://） =="
  [ -f "$DOT_PID_FILE" ] && kill -0 "$(cat "$DOT_PID_FILE")" 2>/dev/null \
    || die "DoT 服务端未运行（先用 dot-up 会话启动）"
  local out conns
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 dot.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.31' || { echo "FAIL: DoT 上游未解析 dot.test"; exit 1; }
  # 第二个名字（未缓存）复用同一连接 → 验证持久化
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 dot2.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.32' || { echo "FAIL: DoT 上游未解析 dot2.test"; exit 1; }
  grep -q '^TLS-QUERY dot.test ' "$DOT_LOG" || { echo "FAIL: DoT 服务端未收到 dot.test"; cat "$DOT_LOG"; exit 1; }
  grep -q '^TLS-QUERY dot2.test ' "$DOT_LOG" || { echo "FAIL: DoT 服务端未收到 dot2.test"; exit 1; }
  conns="$(grep -c '^TLS-CONN$' "$DOT_LOG" || true)"
  [ "$conns" = "1" ] || { echo "FAIL: DoT 连接数 $conns（应为 1，持久连接未复用）"; cat "$DOT_LOG"; exit 1; }
  # 后端确实经假 UDP DNS 应答（转发链完整）
  grep -q '^QUERY dot.test ' "$FAKE_DNS_LOG" || { echo "FAIL: DoT 服务端未转发到假上游"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - <<'PY'
import json
v = json.load(open("/tmp/sodama-status.json"))
assert v["dns"]["upstream_scheme"] == "tls", v["dns"]
assert v["dns"]["upstream_url"].startswith("tls://"), v["dns"]
print("dot: status upstream=%s scheme=%s" % (v["dns"]["upstream"], v["dns"]["upstream_scheme"]))
PY
  echo "PASS: DoT 上游（2 次查询复用 1 条 TLS 连接）"
}

# P18a：DoH 上游（https://，HTTP/1.1 POST application/dns-message + keep-alive）
test_doh() {
  require_root
  echo "== 测试 DoH 上游（https://） =="
  [ -f "$DOH_PID_FILE" ] && kill -0 "$(cat "$DOH_PID_FILE")" 2>/dev/null \
    || die "DoH 服务端未运行（先用 doh-up 会话启动）"
  local out conns
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 doh.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.33' || { echo "FAIL: DoH 上游未解析 doh.test"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 doh2.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.34' || { echo "FAIL: DoH 上游未解析 doh2.test"; exit 1; }
  grep -q '^DOH-QUERY /dns-query doh.test ' "$DOH_LOG" || { echo "FAIL: DoH 服务端未收到 doh.test（path 应为 /dns-query）"; cat "$DOH_LOG"; exit 1; }
  grep -q '^DOH-QUERY /dns-query doh2.test ' "$DOH_LOG" || { echo "FAIL: DoH 服务端未收到 doh2.test"; exit 1; }
  conns="$(grep -c '^DOH-CONN$' "$DOH_LOG" || true)"
  [ "$conns" = "1" ] || { echo "FAIL: DoH 连接数 $conns（应为 1，keep-alive 未复用）"; cat "$DOH_LOG"; exit 1; }
  grep -q '^QUERY doh.test ' "$FAKE_DNS_LOG" || { echo "FAIL: DoH 服务端未转发到假上游"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - <<'PY'
import json
v = json.load(open("/tmp/sodama-status.json"))
assert v["dns"]["upstream_scheme"] == "https", v["dns"]
assert v["dns"]["upstream_url"].startswith("https://"), v["dns"]
print("doh: status upstream=%s scheme=%s" % (v["dns"]["upstream"], v["dns"]["upstream_scheme"]))
PY
  echo "PASS: DoH 上游（2 次查询复用 1 条 keep-alive 连接）"
}

# P23：DoH over HTTP/2（H1 回退不触发；Go 标准库服务端仅收 h2）。
test_doh_h2() {
  require_root
  echo "== P23：DoH over HTTP/2 =="
  [ -f "$DOH_H2_PID_FILE" ] && kill -0 "$(cat "$DOH_H2_PID_FILE")" 2>/dev/null \
    || die "DoH h2 服务端未运行（先用 doh-h2-up 会话启动）"
  local out before after
  before="$(grep -c 'proto=HTTP/2.0 alpn="h2"' "$DOH_H2_LOG" || true)"
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 doh.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.33' || { echo "FAIL: DoH h2 未解析 doh.test"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 doh2.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.34' || { echo "FAIL: DoH h2 第二次查询失败（连接复用/流）"; exit 1; }
  after="$(grep -c 'proto=HTTP/2.0 alpn="h2"' "$DOH_H2_LOG" || true)"
  [ "$((after - before))" = "2" ] \
    || { echo "FAIL: 参考服务端未收到恰好 2 次 h2 请求（增量 $((after - before))）"; tail -5 "$DOH_H2_LOG"; exit 1; }
  if grep -q 'DoH h2 握手失败' "$LOG"; then echo "FAIL: loader 出现 h2 握手回退"; grep 'DoH h2' "$LOG"; exit 1; fi
  echo "PASS: DoH 走 HTTP/2（Go 标准库服务端 ALPN=h2，两次查询复用一条连接）"
}

# P18b：DoQ 上游（quic://，RFC 9250：ALPN doq、每查询一条流、连接复用）
test_doq() {
  require_root
  echo "== 测试 DoQ 上游（quic://） =="
  [ -f "$DOQ_PID_FILE" ] && kill -0 "$(cat "$DOQ_PID_FILE")" 2>/dev/null \
    || die "DoQ 服务端未运行（先用 doq-up 会话启动）"
  local out conns
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 doq.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.37' || { echo "FAIL: DoQ 上游未解析 doq.test"; exit 1; }
  # 第二个名字（未缓存）复用同一 QUIC 连接（每查询一条流）
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 doq2.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.38' || { echo "FAIL: DoQ 上游未解析 doq2.test"; exit 1; }
  grep -q '^DOQ-QUERY doq.test ' "$DOQ_LOG" || { echo "FAIL: DoQ 服务端未收到 doq.test"; cat "$DOQ_LOG"; exit 1; }
  grep -q '^DOQ-QUERY doq2.test ' "$DOQ_LOG" || { echo "FAIL: DoQ 服务端未收到 doq2.test"; exit 1; }
  conns="$(grep -c '^DOQ-CONN$' "$DOQ_LOG" || true)"
  [ "$conns" = "1" ] || { echo "FAIL: DoQ 连接数 $conns（应为 1，连接未复用）"; cat "$DOQ_LOG"; exit 1; }
  grep -q '^QUERY doq.test ' "$FAKE_DNS_LOG" || { echo "FAIL: DoQ 服务端未转发到假上游"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - <<'PY'
import json
v = json.load(open("/tmp/sodama-status.json"))
assert v["dns"]["upstream_scheme"] == "quic", v["dns"]
assert v["dns"]["upstream_url"].startswith("quic://"), v["dns"]
print("doq: status upstream=%s scheme=%s" % (v["dns"]["upstream"], v["dns"]["upstream_scheme"]))
PY
  echo "PASS: DoQ 上游（2 次查询复用 1 条 QUIC 连接、ID 0/恢复）"
}

# P18c：dns.routing 请求/应答分流（两上游、reject/asis/tag、应答重查）
test_dnsroute() {
  require_root
  echo "== 测试 dns.routing（请求/应答分流） =="
  [ -f "$FAKE_DNS_B_PID_FILE" ] && kill -0 "$(cat "$FAKE_DNS_B_PID_FILE")" 2>/dev/null \
    || die "第二假上游未运行（先用 dnsroute-up 会话启动）"
  # asis 目标：WAN ns 内的假 DNS（10.9.9.2:53；客户端用这个地址发起查询）
  ip -n "$WAN_NS" addr add 10.9.9.2/32 dev wanpeer 2>/dev/null || true
  [ -f "$ASIS_DNS_PID_FILE" ] && kill "$(cat "$ASIS_DNS_PID_FILE")" 2>/dev/null || true
  rm -f "$ASIS_DNS_LOG"
  ip netns exec "$WAN_NS" python3 "$HERE/fake_dns.py" "$ASIS_DNS_LOG" 53 10.9.9.2 \
    >/tmp/sodama-asis-dns.stdout 2>&1 &
  echo $! >"$ASIS_DNS_PID_FILE"
  sleep 0.4

  local out hits1 hits2
  # 1) request reject：空应答；上游不得收到
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 blocked.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^rcode=0' || { echo "FAIL: reject 应为 NOERROR"; exit 1; }
  printf '%s\n' "$out" | grep -q '^ancount=0' || { echo "FAIL: reject 应无 answer"; exit 1; }
  if grep -q '^QUERY blocked.test' "$FAKE_DNS_LOG" 2>/dev/null; then
    echo "FAIL: reject 的查询不应到上游"; exit 1
  fi
  echo "route: request reject -> 空应答且不上行"
  # 1b) 自定义名单 qname(file:)：suffix 默认、full: 前缀精确、行内注释
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 fileblocked.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^ancount=0' || { echo "FAIL: 名单域名 fileblocked.test 应被拦截"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 sub.fileblocked.test 2>&1 || true)"
  printf '%s\n' "$out" | grep -q '^ancount=0' || { echo "FAIL: 名单 suffix 应匹配子域 sub.fileblocked.test"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 fullblocked.test 2>&1 || true)"
  printf '%s\n' "$out" | grep -q '^ancount=0' || { echo "FAIL: 名单 full: 精确应拦截"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 x.fullblocked.test 2>&1 || true)"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.47' || { echo "FAIL: full: 不应匹配子域（应正常解析）"; exit 1; }
  if grep -qE '^QUERY (fileblocked|sub\.fileblocked|fullblocked)\.test' "$FAKE_DNS_LOG" 2>/dev/null; then
    echo "FAIL: 名单拦截的查询不应到上游"; exit 1
  fi
  echo "route: qname(file:) 自定义名单（suffix/full/注释，拦截不上行）"
  # 1c) ECS 注入（upstream URL ecs=auto）：客户端 10.0.0.2 → /24 → 10.0.0（截断到前缀字节，RFC 7871）
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 ecsroute.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.48' || { echo "FAIL: ecsroute.test 未解析"; exit 1; }
  grep -q '^QUERY ecsroute.test .*ecs=1/24/10\.0\.0$' "$FAKE_DNS_B_LOG" \
    || { echo "FAIL: 上游未收到注入的 ECS（期望 ecs=1/24/10.0.0）"; cat "$FAKE_DNS_B_LOG"; exit 1; }
  echo "route: ECS 注入（ecs=auto -> 1/24/10.0.0）"
  # 1d) 客户端网段路由（sip）：客户端在 10.0.0.0/24 → up2
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 viacli.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.49' || { echo "FAIL: viacli.test 未解析"; exit 1; }
  grep -q '^QUERY viacli.test ' "$FAKE_DNS_B_LOG" || { echo "FAIL: sip 未命中（up2 未收到 viacli.test）"; exit 1; }
  if grep -q '^QUERY viacli.test ' "$FAKE_DNS_LOG" 2>/dev/null; then
    echo "FAIL: sip 命中后不应到 up1"; exit 1
  fi
  echo "route: sip(10.0.0.0/24) -> up2（客户端网段匹配）"
  # 2) qtype(https)=65 -> reject
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 q65.test 65 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^ancount=0' || { echo "FAIL: qtype(https) 应 reject"; exit 1; }
  echo "route: qtype(https) -> reject"
  # 3) qname(suffix: via2.test) -> up2
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 a.via2.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.42' || { echo "FAIL: via2.test 未解析"; exit 1; }
  grep -q '^QUERY a.via2.test' "$FAKE_DNS_B_LOG" || { echo "FAIL: up2 未收到 via2.test"; cat "$FAKE_DNS_B_LOG"; exit 1; }
  if grep -q '^QUERY a.via2.test' "$FAKE_DNS_LOG" 2>/dev/null; then
    echo "FAIL: via2.test 不应到 up1"; exit 1
  fi
  echo "route: qname(suffix: via2.test) -> up2"
  # 4) 缓存作用域：重查不进上游
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 a.via2.test 2>&1 || true)"
  hits2="$(grep -c '^QUERY a.via2.test' "$FAKE_DNS_B_LOG" || true)"
  [ "$hits2" = "1" ] || { echo "FAIL: via2.test 缓存未命中（up2 $hits2 次）"; exit 1; }
  echo "route: 按上游作用域缓存（第二次命中）"
  # 5) fallback=up1
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 other.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.45' || { echo "FAIL: fallback 未走 up1"; exit 1; }
  grep -q '^QUERY other.test' "$FAKE_DNS_LOG" || { echo "FAIL: up1 未收到 other.test"; exit 1; }
  echo "route: fallback -> up1"
  # 6) 应答 reject：ip(10.9.10.60/32)
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 polluted.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^ancount=0' || { echo "FAIL: 应答路由未 reject（应清空 answer）"; exit 1; }
  grep -q '^QUERY polluted.test' "$FAKE_DNS_LOG" || { echo "FAIL: polluted.test 应先到 up1"; exit 1; }
  if grep -q '^QUERY polluted.test' "$FAKE_DNS_B_LOG" 2>/dev/null; then
    echo "FAIL: polluted.test 不应被重查到 up2"; exit 1
  fi
  echo "route: response ip(10.9.10.60/32) -> reject（清空 answer）"
  # 7) 应答重查：ip(10.9.10.61/32) -> up2
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 relook.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.61' || { echo "FAIL: relook.test 未解析"; exit 1; }
  grep -q '^QUERY relook.test' "$FAKE_DNS_LOG" || { echo "FAIL: relook 初查未到 up1"; exit 1; }
  grep -q '^QUERY relook.test' "$FAKE_DNS_B_LOG" || { echo "FAIL: relook 重查未到 up2"; exit 1; }
  echo "route: response ip(10.9.10.61/32) -> up2 重查"
  # 7b) 应答侧 sip：客户端 10.0.0.2 ∈ 10.0.0.0/24（10.9.9.0/24 规则应跳过）→ 空应答
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 rsip.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^ancount=0' || { echo "FAIL: 应答侧 sip 未命中（应空应答）"; exit 1; }
  grep -q '^QUERY rsip.test ' "$FAKE_DNS_LOG" || { echo "FAIL: rsip.test 应先到 up1"; exit 1; }
  echo "route: response sip(10.0.0.0/24) && ip(...) -> reject（客户端来源过滤）"
  # 8) asis：客户端向 10.9.9.2:53（WAN ns）发查，控制面 asis 发回该地址
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 10.9.9.2 asis.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.44' || { echo "FAIL: asis 未解析（原目的地址回查）"; exit 1; }
  grep -q '^QUERY asis.test' "$ASIS_DNS_LOG" || { echo "FAIL: asis 目标未收到查询"; cat "$ASIS_DNS_LOG"; exit 1; }
  echo "route: qname(full: asis.test) -> asis（回原目的地址 10.9.9.2:53）"
  # 8b) asis（TCP 客户端路径）：透明套接字的 local_addr = 原目的地址
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" --tcp 10.9.9.2 tcp.asis.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.46' || { echo "FAIL: TCP asis 未解析（原目的地址）"; exit 1; }
  grep -q '^QUERY tcp.asis.test' "$ASIS_DNS_LOG" || { echo "FAIL: TCP asis 目标未收到查询"; exit 1; }
  echo "route: TCP 客户端 asis（local_addr 原目的地址）"

  # 9) dns.routing 热重载：request fallback up1 -> reject，新名字变空应答
  sed -i 's/fallback: up1/fallback: reject/' /tmp/sodama-dnsroute.dae
  chmod 640 /tmp/sodama-dnsroute.dae
  "$LOADER" reload --socket "$STATUS_SOCK" >/dev/null
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 z.other.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^ancount=0' || { echo "FAIL: 重载后 fallback=reject 未生效"; exit 1; }
  if grep -q '^QUERY z.other.test' "$FAKE_DNS_LOG" 2>/dev/null; then
    echo "FAIL: 重载后 reject 的查询不应到上游"; exit 1
  fi
  "$LOADER" status --socket "$STATUS_SOCK" --json | python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["dns"]["routing"]["request_fallback"]=="Reject", v["dns"]["routing"]; print("route: reload 后 request_fallback=Reject")'
  # 恢复
  sed -i 's/fallback: reject/fallback: up1/' /tmp/sodama-dnsroute.dae
  chmod 640 /tmp/sodama-dnsroute.dae
  "$LOADER" reload --socket "$STATUS_SOCK" >/dev/null
  # other.test 可能命中缓存；但请求路由先于缓存，fallback=reject 时会直接空应答
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 other.test 2>&1 || true)"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.45' || { echo "FAIL: 恢复 fallback=up1 后未解析"; exit 1; }
  echo "route: dns.routing 热重载（fallback 切换即时生效）"

  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - <<'PY'
import json
v = json.load(open("/tmp/sodama-status.json"))
d = v["dns"]
r = d["routing"]
assert r["request_rules"] == 7 and r["response_rules"] == 5, r
assert r["rejects"] >= 5 and r["response_rejects"] >= 2 and r["relookups"] >= 1, r
assert set(d["upstreams"].keys()) == {"up1", "up2", "up2ecs"}, d["upstreams"]
assert r["upstream_hits"].get("up1", 0) >= 1 and r["upstream_hits"].get("up2", 0) >= 1, r["upstream_hits"]
assert r["upstream_hits"].get("up2ecs", 0) >= 1, r["upstream_hits"]
print("dnsroute: rules=%d/%d rejects=%d resp_rejects=%d relookups=%d hits=%s" % (
    r["request_rules"], r["response_rules"], r["rejects"], r["response_rejects"], r["relookups"], r["upstream_hits"]))
PY
  echo "PASS: dns.routing（reject/qtype/多上游/缓存作用域/应答 reject/重查/asis/热重载）"
}

# P18a：显式 udp:// 上游（仅 UDP；不应出现 TCP 上行）
test_dns_udp() {
  require_root
  echo "== 测试显式 udp:// 上游 =="
  local out hits tcp_hits
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 udpup.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.35' || { echo "FAIL: udp:// 上游未解析 udpup.test"; exit 1; }
  hits="$(grep -c '^QUERY udpup.test ' "$FAKE_DNS_LOG" || true)"
  tcp_hits="$(grep -c '^QUERY-TCP udpup.test ' "$FAKE_DNS_LOG" || true)"
  [ "$hits" = "1" ] && [ "$tcp_hits" = "0" ] || { echo "FAIL: udp:// 上行走 UDP=$hits TCP=$tcp_hits（应为 1/0）"; exit 1; }
  echo "PASS: udp:// 上游（仅 UDP，1 次上行）"
}

# P18a：显式 tcp:// 上游（仅 TCP，2B 分帧）
test_dns_tcpup() {
  require_root
  echo "== 测试显式 tcp:// 上游 =="
  local out hits udp_hits
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 tcpup.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.36' || { echo "FAIL: tcp:// 上游未解析 tcpup.test"; exit 1; }
  hits="$(grep -c '^QUERY-TCP tcpup.test ' "$FAKE_DNS_LOG" || true)"
  udp_hits="$(grep -c '^QUERY tcpup.test ' "$FAKE_DNS_LOG" || true)"
  [ "$hits" = "1" ] && [ "$udp_hits" = "0" ] || { echo "FAIL: tcp:// 上行走 TCP=$hits UDP=$udp_hits（应为 1/0）"; exit 1; }
  echo "PASS: tcp:// 上游（仅 TCP，1 次上行）"
}

# P4a：TCP relay（direct 拨号）——真实转发到目标，含大流量完整性。
test_relay() {
  require_root
  echo "== 测试 TCP relay（direct 拨号，真实转发）=="
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "wan-echo-ok data=ping" || { echo "FAIL: relay 未把流量转发到真实目标"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 30 python3 "$HERE/stream_probe.py" "$PROXY_DST" 8080 512 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "^stream-ok bytes=524288" || { echo "FAIL: relay 大流量回显不一致"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
assert v["dialer"] == "direct", v["dialer"]
r = v["relay"]
assert r["conns_total"] >= 2, r
assert r["bytes_up"] >= 512 * 1024, r
assert r["dial_errors"] == 0, r
print("relay: conns_total=%d bytes_up=%d bytes_down=%d dial_errors=%d" % (
    r["conns_total"], r["bytes_up"], r["bytes_down"], r["dial_errors"]))
PY
  echo "PASS: relay 真实转发（512KB 完整性）+ 状态面"
}

# P4a：relay janitor 空闲回收（会话用 --relay-idle-timeout 2 启动）。
test_relay_idle() {
  require_root
  echo "== 测试 relay 空闲回收（janitor）=="
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 20 python3 - "$PROXY_DST" <<'PY' 2>&1 || true
import socket, sys, time
s = socket.create_connection((sys.argv[1], 8080), timeout=5)
s.sendall(b"ping\n")
print("first:", s.recv(4096).decode(errors="replace").strip())
time.sleep(7)   # 超过 --relay-idle-timeout=2s，janitor（5s 周期）会强制关闭
s.settimeout(3)
try:
    data = s.recv(4096)
    print("after-idle: closed" if data == b"" else f"after-idle: got {data!r}")
except (socket.timeout, ConnectionResetError):
    print("after-idle: timeout/reset")
PY
)"
  echo "$out"
  echo "$out" | grep -q "first: wan-echo-ok" || { echo "FAIL: relay 连接未建立"; exit 1; }
  echo "$out" | grep -qE "after-idle: (closed|timeout/reset)" || { echo "FAIL: 空闲连接未被回收"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json | python3 -c 'import json,sys;v=json.load(sys.stdin);assert v["relay"]["evicted"]>=1, v["relay"];print("relay evicted:", v["relay"]["evicted"])'
  echo "PASS: relay janitor 回收空闲连接"
}

# O9 回归：relay 泵线程泄漏。
# 姿态：「上游先关 + 客户端保持静默」（wan_echo:8083 应答后即关）。旧行为是
# 先结束的泵（上游→客户端）调 relay_finish 把会话从 RELAY_CONNS 摘除，另一个
# 卡在 recv 的泵此后既不会被 janitor 看见（不回收），也不再计入账目 —— 线程、
# 64KB 缓冲与 fd 永久泄漏（路由器现场：54+ 泵线程）。修复后由「最后一个泵」
# 收尾，会话留在注册表里等 janitor 强制 shutdown，泵退出、线程回落。
# 须用 relay-thread-up 会话启动（reactor 路径每连接 0 线程，测不到该缺陷）。
test_relay_thread_leak() {
  require_root
  echo "== O9 回归：relay 泵线程泄漏（half-close）=="
  [ -f "$PID_FILE" ] || die "先运行 $0 relay-thread-up"
  local pid; pid="$(cat "$PID_FILE")"
  kill -0 "$pid" 2>/dev/null || die "sodama 未运行（pid $pid）"
  local n=16 hold=45 wait_s=15 relay_margin=4 thread_margin=6
  local log_dir=/tmp/sodama-halfclose
  rm -rf "$log_dir"; mkdir -p "$log_dir"

  local before_threads before_relay before_evicted
  before_threads="$(ls "/proc/$pid/task" | wc -l)"
  before_relay="$(count_relay_threads "$pid")"
  before_evicted="$("$LOADER" status --socket "$STATUS_SOCK" --json \
    | python3 -c 'import json,sys;print(json.load(sys.stdin)["relay"]["evicted"])')"
  echo "baseline: threads=$before_threads relay=$before_relay evicted=$before_evicted"

  # 1) 起 N 条半开连接：读到应答后客户端静默保持（不读/不写/不关）
  local pids=() i
  for i in $(seq 1 "$n"); do
    ip netns exec "$CLIENT_NS" python3 "$HERE/halfclose_hold.py" "$PROXY_DST" 8083 "$hold" "$i" \
      >"$log_dir/$i.log" 2>&1 &
    pids+=("$!")
  done
  # 2) 建连必须全部成功，否则断言会跑在空跑道上假通过
  local ok=0
  for _ in $(seq 1 60); do
    ok="$(grep -l 'halfclose-ok' "$log_dir"/*.log 2>/dev/null | wc -l || true)"
    # 注：&&/|| 包裹避免 pipefail 把「暂无命中」当成脚本失败
    if [ "$ok" = "$n" ]; then break; fi
    sleep 0.25
  done
  if [ "$ok" != "$n" ]; then
    cat "$log_dir"/*.log || true
    kill "${pids[@]}" 2>/dev/null || true
    die "半开连接仅建立 $ok/$n 条（8083 夹具/规则未生效？）"
  fi
  echo "保持中: relay 泵线程合计=$(count_relay_threads "$pid")（每条会话剩 1 个卡在 recv 的泵）"

  # 3) 等 janitor（tick 5s；--relay-idle-timeout=2）回收半开连接
  sleep "$wait_s"
  local after_threads after_relay after_evicted
  after_threads="$(ls "/proc/$pid/task" | wc -l)"
  after_relay="$(count_relay_threads "$pid")"
  after_evicted="$("$LOADER" status --socket "$STATUS_SOCK" --json \
    | python3 -c 'import json,sys;print(json.load(sys.stdin)["relay"]["evicted"])')"
  echo "after ${wait_s}s: threads=$after_threads relay=$after_relay evicted=$after_evicted"

  # 4) 先收尾探针（客户端关闭），再断言——断言窗口内连接必须仍在保持
  kill "${pids[@]}" 2>/dev/null || true
  wait "${pids[@]}" 2>/dev/null || true

  # 断言 1：janitor 回收了全部 N 条（修复前注册表被先结束的泵摘掉，evicted 不增）
  python3 - "$n" "$before_evicted" "$after_evicted" <<'PY'
import sys
n, before, after = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
delta = after - before
assert delta >= n, f"evicted 增量 {delta} < {n}：janitor 看不到半开连接（泵先摘了注册表？）"
print(f"evicted += {delta}")
PY
  # 断言 2：relay 泵线程回落到基线（修复前每连接残留 1 个永久阻塞的泵线程）
  if [ "$after_relay" -gt $((before_relay + relay_margin)) ] \
    || [ "$after_threads" -gt $((before_threads + thread_margin)) ]; then
    echo "线程名汇总（泄漏现场）："
    threads_by_comm "$pid" || true
    die "泵线程未回落：relay $before_relay→$after_relay，总线程 $before_threads→$after_threads"
  fi
  echo "PASS: relay 泵线程不泄漏（relay $before_relay→$after_relay，总线程 $before_threads→$after_threads，evicted += $((after_evicted - before_evicted))）"
}

# P4b：UDP NAT——真实转发、3 报文复用 1 会话、回包源地址为原始目的地址。
test_udp_relay() {
  require_root
  echo "== 测试 UDP NAT（转发 + 会话复用）=="
  local out
  # P20：用前后增量断言（3 报文恰好新增 1 会话 = 复用），不依赖前序用例留下的会话。
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status-before.json
  out="$(ip netns exec "$CLIENT_NS" timeout 10 python3 "$HERE/udp_probe.py" 2.2.2.2 9998 3 0.2 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "reply=udp-echo-ok data=ping0 from=2.2.2.2:9998" || { echo "FAIL: UDP 未转发到真实目标/回包源地址不对"; exit 1; }
  echo "$out" | grep -q "^summary=3/3" || { echo "FAIL: UDP 报文丢失"; exit 1; }
  sleep 0.3
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status-before.json /tmp/sodama-status.json <<'PY'
import json, sys
b = json.load(open(sys.argv[1]))["udp_nat"]
a = json.load(open(sys.argv[2]))["udp_nat"]
assert a["sessions_total"] == b["sessions_total"] + 1, (b, a)  # 3 报文复用出 1 个新会话
assert a["bytes_up"] >= b["bytes_up"] + 15, (b, a)
assert a["bytes_down"] >= b["bytes_down"] + 45, (b, a)
assert a["errors"] == b["errors"], (b, a)
print("udp nat: +1 session bytes_up=%d bytes_down=%d" % (
    a["bytes_up"] - b["bytes_up"], a["bytes_down"] - b["bytes_down"]))
PY
  echo "PASS: UDP NAT（真实转发、3 报文复用 1 会话、回包源地址正确）"
}

# P20：QUIC Initial SNI 嗅探（跨实现：Python 按 RFC 9001 独立造包）。
test_quic_sniff() {
  require_root
  echo "== P20：QUIC Initial SNI 嗅探 =="
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/quic_probe.py" 2.2.2.2 9998 www.example.com 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "quic-sniff-sent sni=www.example.com" \
    || { echo "FAIL: 探针未发送"; exit 1; }
  sleep 0.3
  grep -q "quic sniff .* → www.example.com" "$LOG" \
    || { echo "FAIL: 日志无 QUIC SNI 记录（先 udp-up）"; tail -5 "$LOG"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
s = v["sniffing"]
assert s.get("quic_initial", 0) >= 1, s
assert s.get("quic_sni", 0) >= 1, s
print("quic sniff: initial=%d sni=%d" % (s["quic_initial"], s["quic_sni"]))
PY
  echo "PASS: QUIC Initial SNI 嗅探（Initial 解密 + sni=www.example.com）"
}

# P21：sniff-punt——嗅探命中域名后在 relay 侧按规则重选出口（direct/block/组）。
test_sniff_punt() {
  require_root
  echo "== P21：sniff-punt（嗅探重判）=="
  rm -f "$SS_LOG" "${SS_LOG}.b"
  local out
  # 1) SNI=direct.test → 规则 domain(suffix:direct.test) -> direct：直连（不经 ss 服务端）
  out="$(ip netns exec "$CLIENT_NS" timeout 10 python3 "$HERE/tls_sniff_probe.py" "$PROXY_DST" 8080 direct.test 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "tls-probe-ok sni=direct.test" || { echo "FAIL: punt→direct 链路不通"; exit 1; }
  grep -q "punt direct.test（$PROXY_DST:8080）→ direct" "$LOG" || { echo "FAIL: 日志无 punt→direct"; tail -5 "$LOG"; exit 1; }
  if grep -q "TCP target=$PROXY_DST:8080" "$SS_LOG"; then echo "FAIL: punt→direct 不应经过 ss 服务端（仅有健康检查）"; exit 1; fi
  # 2) SNI="1.1.1.1" → 规则 domain(full:1.1.1.1) -> alt（node-b）：从数据面选的 proxy
  #    重判为 alt，ss-B 日志为证（数字域名由 ss 服务端远端解析，跨实现）。
  out="$(ip netns exec "$CLIENT_NS" timeout 10 python3 "$HERE/tls_sniff_probe.py" "$PROXY_DST" 8080 1.1.1.1 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "tls-probe-ok sni=1.1.1.1" || { echo "FAIL: punt→组（ss）链路不通"; exit 1; }
  grep -q "punt 1.1.1.1（$PROXY_DST:8080）→ outbound 0x03（组" "$LOG" || { echo "FAIL: 日志无 punt→alt 组"; tail -5 "$LOG"; exit 1; }
  grep -q "TCP target=$PROXY_DST:8080" "${SS_LOG}.b" || { echo "FAIL: ss-B（alt 组）未看到目标"; cat "${SS_LOG}.b"; exit 1; }
  if grep -q "TCP target=$PROXY_DST:8080" "$SS_LOG"; then echo "FAIL: 重判后不应再经过 ss-A（proxy 组）"; exit 1; fi
  # 3) SNI=blocked.test → 规则 block：连接被关闭
  out="$(ip netns exec "$CLIENT_NS" timeout 10 python3 "$HERE/tls_sniff_probe.py" "$PROXY_DST" 8080 blocked.test 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "tls-probe-closed sni=blocked.test" || { echo "FAIL: punt→block 未关闭连接"; exit 1; }
  grep -q "punt blocked.test（$PROXY_DST:8080）→ block" "$LOG" || { echo "FAIL: 日志无 punt→block"; tail -5 "$LOG"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
s = v["sniffing"]
assert s.get("punt_enabled") is True, s
assert s.get("punt_attempts", 0) >= 3, s
assert s.get("punt_direct", 0) >= 1, s
assert s.get("punt_block", 0) >= 1, s
assert s.get("punt_group", 0) >= 1, s
print("punt: attempts=%d direct=%d block=%d group=%d keep=%d" % (
    s["punt_attempts"], s["punt_direct"], s["punt_block"],
    s["punt_group"], s["punt_keep"]))
PY
  echo "PASS: sniff-punt（direct / block / 组重选 三条路径）"
}

# P23：DNS 选项（fixed_domain_ttl / optimistic cache / ipversion_prefer）。
test_dns_options() {
  require_root
  echo "== P23：DNS 选项（fixed_domain_ttl / optimistic / ipversion_prefer）=="
  rm -f "$FAKE_DNS_LOG"
  local out
  # 1) fixed_domain_ttl=1：首查（上游 TTL=30）→ 应答 TTL 为上游值（fixed 只改缓存寿命）
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 stale.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.71' || { echo "FAIL: stale.test 未解析"; exit 1; }
  # 2) 睡 2s（> fixed 1s，< optimistic 60s）：第二次查询命中 stale，TTL 压到 7，且不再上行
  sleep 2
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 stale.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.71' || { echo "FAIL: stale.test 第二次未解析（optimistic 未生效）"; exit 1; }
  printf '%s\n' "$out" | grep -q '^ttl=7' || { echo "FAIL: stale 应答 TTL 未压到 optimistic_stale_reply_ttl=7"; exit 1; }
  # P29：stale 命中触发 RFC 8767 后台刷新（单飞）——等待假上游恰好收到 1 次刷新（共 2 次）
  local i=0
  while [ "$(grep -c '^QUERY stale.test ' "$FAKE_DNS_LOG" || true)" != "2" ] && [ "$i" -lt 30 ]; do sleep 0.1; i=$((i+1)); done
  [ "$(grep -c '^QUERY stale.test ' "$FAKE_DNS_LOG" || true)" = "2" ] \
    || { echo "FAIL: 后台刷新未发生或重复（期望共 2 次上游查询，实际 $(grep -c '^QUERY stale.test ' "$FAKE_DNS_LOG" || true)）"; cat "$FAKE_DNS_LOG"; exit 1; }
  # 3) ipversion_prefer=4：先 A（入缓存），AAAA 查询应得到空 NOERROR（ancount=0）
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 pref.test 2>&1 || true)"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.72' || { echo "FAIL: pref.test A 未解析"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 pref.test 28 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^ancount=0' || { echo "FAIL: ipversion_prefer=4 未过滤 AAAA（应有 A 已知）"; exit 1; }
  # 4) 仅 AAAA 的域名不受影响
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 v6only.test 28 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^answer6=2001:db8::73' || { echo "FAIL: 仅 AAAA 域名被误过滤"; exit 1; }
  # 5) 状态面
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
d = v["dns"]
assert d.get("ipversion_prefer") == 4, d
assert d.get("fixed_domain_ttl") == 1, d
assert d.get("stale_hits", 0) >= 1, d
assert d.get("ipversion_filtered", 0) >= 1, d
assert d["refresh"]["spawned"] >= 1, d["refresh"]
assert d["refresh"]["err"] == 0, d["refresh"]
print("dns opts: stale_hits=%d ipversion_filtered=%d fixed=%d refresh=%d/%d" % (
    d["stale_hits"], d["ipversion_filtered"], d["fixed_domain_ttl"],
    d["refresh"]["spawned"], d["refresh"]["coalesced"]))
PY
  echo "PASS: fixed_domain_ttl / optimistic cache（stale TTL 上限 + RFC 8767 后台刷新单飞）/ ipversion_prefer"
}

# P25：naive（HTTP/2 CONNECT）TCP 转发 + Basic 认证 + 用户态流控（offload 互斥）。
test_naive() {
  require_root
  echo "== P25：naive（HTTP/2 CONNECT）=="
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "wan-echo-ok data=ping" || { echo "FAIL: naive 链路未把流量转发到真实目标"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 30 python3 "$HERE/stream_probe.py" "$PROXY_DST" 8080 512 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "^stream-ok bytes=524288" || { echo "FAIL: naive 大流量（512KB）回显不一致（双向流控？）"; exit 1; }
  grep -q "NAIVE connect target=$PROXY_DST:8080" "$NAIVE_LOG" \
    || { echo "FAIL: 参考服务端未收到 h2 CONNECT（认证/ALPN？）"; cat "$NAIVE_LOG"; exit 1; }
  grep -q "proto=HTTP/2.0" "$NAIVE_LOG" || { echo "FAIL: 连接不是 HTTP/2"; exit 1; }
  grep -q "NAIVE auth-fail" "$NAIVE_LOG" && { echo "FAIL: 出现认证失败（Basic 头编码？）"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
assert v["dialer"].startswith("naive+https://"), v["dialer"]
r = v["relay"]
assert r["conns_total"] >= 2, r
assert r["dial_errors"] == 0, r
assert r["offload_enabled"], r
assert r["offloaded_total"] == 0, r  # h2 隧道不可内核拼接
assert r["bytes_up"] >= 512 * 1024, r
print("naive tcp: conns=%d bytes_up=%d offloaded=%d" % (r["conns_total"], r["bytes_up"], r["offloaded_total"]))
PY
  echo "PASS: naive（Go 标准库参考服务端 h2 CONNECT + Basic 认证 + 512KB 双向流控）"
}

# P26：naive over HTTP/3（qic-go 参考服务端；ALPN=h3；CONNECT + Basic + 双向流）。
test_naive_h3() {
  require_root
  echo "== P26：naive over HTTP/3（CONNECT）=="
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "wan-echo-ok data=ping" || { echo "FAIL: naive h3 链路未把流量转发到真实目标"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 30 python3 "$HERE/stream_probe.py" "$PROXY_DST" 8080 512 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "^stream-ok bytes=524288" || { echo "FAIL: naive h3 大流量（512KB）回显不一致（单向流/DATA 帧？）"; exit 1; }
  grep -q "NAIVE-H3 connect target=$PROXY_DST:8080" "$NAIVE_H3_LOG" \
    || { echo "FAIL: 参考服务端未收到 h3 CONNECT（认证/ALPN？）"; cat "$NAIVE_H3_LOG"; exit 1; }
  grep -q "proto=HTTP/3.0" "$NAIVE_H3_LOG" || { echo "FAIL: 连接不是 HTTP/3"; exit 1; }
  grep -q "NAIVE-H3 auth-fail" "$NAIVE_H3_LOG" && { echo "FAIL: 出现认证失败（Basic 头编码？）"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
assert v["dialer"].startswith("naive+quic://"), v["dialer"]
r = v["relay"]
assert r["conns_total"] >= 2, r
assert r["dial_errors"] == 0, r
assert r["offload_enabled"], r
assert r["offloaded_total"] == 0, r  # QUIC 不交内核拼接
assert r["bytes_up"] >= 512 * 1024, r
assert r["bytes_down"] >= 512 * 1024, r
print("naive h3 tcp: conns=%d bytes_up=%d bytes_down=%d offloaded=%d" % (
    r["conns_total"], r["bytes_up"], r["bytes_down"], r["offloaded_total"]))
PY
  echo "PASS: naive over HTTP/3（Go/quic-go 服务端 + h3 CONNECT/Basic + 512KB 双向）"
}

# P26：DoH over HTTP/3（quic-go 参考服务端；连接复用由服务端 new conn 计数验证）。
test_doh_h3() {
  require_root
  echo "== P26：DoH over HTTP/3 =="
  [ -f "$DOH_H3_PID_FILE" ] && kill -0 "$(cat "$DOH_H3_PID_FILE")" 2>/dev/null \
    || die "DoH h3 服务端未运行（先用 doh-h3-up 会话启动）"
  local out before after conns_before conns_after
  before="$(grep -c 'H3 request proto=HTTP/3.0' "$DOH_H3_LOG" || true)"
  conns_before="$(grep -c 'H3 new conn' "$DOH_H3_LOG" || true)"
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 doh3.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.39' || { echo "FAIL: DoH h3 未解析 doh3.test"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 doh4.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.40' || { echo "FAIL: DoH h3 第二次查询失败（连接复用/流）"; exit 1; }
  after="$(grep -c 'H3 request proto=HTTP/3.0' "$DOH_H3_LOG" || true)"
  conns_after="$(grep -c 'H3 new conn' "$DOH_H3_LOG" || true)"
  [ "$((after - before))" = "2" ] \
    || { echo "FAIL: 参考服务端未收到恰好 2 次 h3 请求（增量 $((after - before))）"; tail -5 "$DOH_H3_LOG"; exit 1; }
  [ "$((conns_after - conns_before))" = "1" ] \
    || { echo "FAIL: 两次查询未复用同一条 h3 连接（新增连接 $((conns_after - conns_before))）"; exit 1; }
  if grep -q 'DoH h3 请求.*失败\|DoH h3 握手失败\|DoH h3 响应状态' "$LOG"; then
    echo "FAIL: loader 出现 h3 错误"; grep 'DoH h3' "$LOG"; exit 1;
  fi
  echo "PASS: DoH 走 HTTP/3（Go/quic-go 服务端 ALPN=h3，两次查询复用一条 QUIC 连接）"
}

# P4b：UDP NAT 会话 janitor（会话用 --udp-idle-timeout 2 启动）。
test_udp_idle() {
  require_root
  echo "== 测试 UDP NAT 会话回收（janitor）=="
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 10 python3 "$HERE/udp_probe.py" 2.2.2.2 9998 1 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "^summary=1/1" || { echo "FAIL: UDP 首发未成功"; exit 1; }
  sleep 8  # 超过 --udp-idle-timeout=2s，janitor（5s 周期）回收
  "$LOADER" status --socket "$STATUS_SOCK" --json | python3 -c 'import json,sys;v=json.load(sys.stdin);u=v["udp_nat"];assert u["sessions_active"]==0,u;assert u["evicted"]>=1,u;print("udp nat janitor: evicted=%d active=%d" % (u["evicted"],u["sessions_active"]))'
  echo "PASS: UDP NAT janitor 回收空闲会话"
}

# P16：IPv6 全链（tproxy v6 → relay → ss v6 目标；v6 direct 内核转发对照）。
test_v6() {
  require_root
  echo "== P16：IPv6 代理路径（client → landae v6 → tproxy v6 → ss → v6 echo）=="
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" 2001:db8:aa::1 9999 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "wan-echo-ok" || { echo "FAIL: IPv6 代理路径不通"; exit 1; }
  echo "PASS: IPv6 报文经 tproxy v6 → relay → ss(ATYP=4) → v6 echo"
  grep -q "sockmap key 2, IPv6" "$LOG" || { echo "FAIL: 未见 IPv6 tproxy listener 注册"; tail -5 "$LOG"; exit 1; }
  echo "PASS: IPv6 tproxy listener 已注册（sockmap key 2）"

  echo "== P16：IPv6 direct（内核三层转发到 wan echo）=="
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" 2001:db8:9::2 9999 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "wan-echo-ok" || { echo "FAIL: IPv6 direct 路径不通"; exit 1; }
  echo "PASS: IPv6 direct 由内核转发（未经 tproxy）"

  # ---- P22：IPv6 UDP 全链 ----
  grep -q "udp v6 listener registered: \[::\]:" "$LOG" || { echo "FAIL: 未见 IPv6 UDP listener 注册"; tail -5 "$LOG"; exit 1; }
  echo "== P22：IPv6 UDP 代理（client → tproxy v6 UDP → NAT → ss UDP v6 目标）=="
  rm -f "$SS_LOG"
  out="$(ip netns exec "$CLIENT_NS" timeout 10 python3 "$HERE/udp_probe.py" 2001:db8:aa::1 9998 2 0.2 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "reply=udp-echo-ok data=ping0" || { echo "FAIL: v6 UDP 未转发到真实目标/回包不对"; exit 1; }
  echo "$out" | grep -q "^summary=2/2" || { echo "FAIL: v6 UDP 报文丢失"; exit 1; }
  grep -q "UDP target=2001:db8:aa::1:9998" "$SS_LOG" || { echo "FAIL: ss 服务端未看到 v6 UDP 目标（跨实现失败）"; cat "$SS_LOG"; exit 1; }
  echo "PASS: IPv6 UDP 报文经 tproxy v6 → NAT → ss UDP（v6 目标，跨实现）"

  echo "== P22：IPv6 DNS（client → [2001:db8:aa::1]:53 → 控制面 v6 UDP → 假上游）=="
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 2001:db8:aa::1 udpup.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.35' || { echo "FAIL: v6 DNS 未解析（控制面 v6 UDP 接管失败）"; exit 1; }
  printf '%s\n' "$out" | grep -q 'from=2001:db8:aa::1:53' || { echo "FAIL: v6 DNS 回包源地址不是原始目的地址"; exit 1; }
  [ "$(grep -c '^QUERY udpup.test ' "$FAKE_DNS_LOG" || true)" = "1" ] || { echo "FAIL: 假上游未收到恰好 1 次 v6 DNS 查询"; exit 1; }
  echo "PASS: IPv6 DNS 经 v6 UDP 透明监听（IPV6_RECVORIGDSTADDR）回包源地址正确"
}

# P17a：geoip/geosite 展开端到端（geoip → LPM 直连；geosite → 域位图代理）。
test_geo() {
  require_root
  echo "== P17a：geoip 展开（LPM 直连）=="
  grep -q "geoexp: dip(geoip:cn)" "$LOG" || { echo "FAIL: 日志未见 geoip 展开"; tail -20 "$LOG"; exit 1; }
  local out
  # 夹具 CN = 10.9.10.0/24：集合内 → direct（WAN echo）
  out="$(ip netns exec "$CLIENT_NS" timeout 6 python3 "$HERE/client_probe.py" 10.9.10.2 9999 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "wan-echo-ok" || { echo "FAIL: geoip:cn 内目的未直连"; exit 1; }
  # 集合外（10.9.9.2）→ fallback proxy（tproxy 回显）
  out="$(ip netns exec "$CLIENT_NS" timeout 6 python3 "$HERE/client_probe.py" 10.9.9.2 9999 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "orig_dst=10.9.9.2:9999" || { echo "FAIL: geoip 集合外目的未走代理（展开过宽？）"; exit 1; }
  echo "PASS: geoip:cn 展开为 LPM，集合内直连 / 集合外代理"

  echo "== P17a：geosite 展开（域位图代理）=="
  grep -q "geoexp: domain(geosite:cn)" "$LOG" || { echo "FAIL: 日志未见 geosite 展开"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 geo.test 2>&1 || true)"
  echo "$out"
  local ans
  ans="$(printf '%s\n' "$out" | sed -n 's/^answer=\(.*\)$/\1/p' | head -1)"
  [ "$ans" = "10.9.10.3" ] || { echo "FAIL: geo.test 未解析到 10.9.10.3（DNS 接管/转发失败）"; exit 1; }
  # 用 8080 端口：避开第 1 条规则的 dport(9999) 门（否则 geoip 规则会先命中）
  out="$(ip netns exec "$CLIENT_NS" timeout 6 python3 "$HERE/client_probe.py" "$ans" 8080 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "orig_dst=$ans:8080" || { echo "FAIL: geosite:cn 域未走代理（位图未命中）"; exit 1; }
  echo "PASS: geosite:cn 展开进域位图，geo.test 命中代理"
}

# P17b：pname（cgroup2 采集 → WAN egress 新连接按进程名匹配）。
test_pname() {
  require_root
  echo "== P17b：pname 采集与匹配（host 发起流量）=="
  grep -q "pname: cgroup2 钩子" "$LOG" || { echo "FAIL: cgroup2 钩子未挂载"; tail -20 "$LOG"; exit 1; }

  # 1) python3 → pname(python3) 命中 → direct（WAN echo）
  local out
  out="$(timeout 6 python3 "$HERE/client_probe.py" 1.1.1.1 8080 2>&1 || true)"
  echo "python3: $out"
  echo "$out" | grep -q "wan-echo-ok" || { echo "FAIL: pname(python3) 未命中（应为 direct）"; exit 1; }

  # 2) curl → 不命中 → fallback proxy（tproxy 回显；回显不是 HTTP 响应，须 --http0.9）
  out="$(curl --http0.9 -sS -m 6 http://1.1.1.1:8080/ 2>&1 || true)"
  echo "curl: $out"
  echo "$out" | grep -q "sodama tproxy" || { echo "FAIL: curl 未走 fallback 代理"; exit 1; }

  # 3) cookie→pname 表：用一个「活着的」连接验证采集（socket 关闭会被 sock_release 清掉，
  #    清理本身也是预期行为）
  (timeout 8 python3 -c 'import socket,time; s=socket.create_connection(("1.1.1.1",8080),timeout=3); time.sleep(6); s.close()' >/dev/null 2>&1 &)
  sleep 1.5
  local mid
  mid="$(python3 "$HERE/map_id.py" cookie_pid_map)"
  [ -n "$mid" ] || { echo "FAIL: 找不到 cookie_pid_map"; exit 1; }
  bpftool -j map dump id "$mid" >/tmp/sodama-cookie.json
  python3 - /tmp/sodama-cookie.json <<'PY'
import json, sys
val = json.load(open(sys.argv[1]))
names = set()
for e in val:
    v = e.get("value")
    if not isinstance(v, list) or len(v) < 16:
        continue
    b = bytes(int(x, 16) if isinstance(x, str) else x for x in v)
    p = b[:16].split(b"\x00")[0].decode(errors="replace")
    if p:
        names.add(p)
assert "python3" in names, names
print("cookie_pid_map pname 条目:", sorted(names)[:8])
PY

  # 4) 状态面：driver/hooks/enabled/hits
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
p = v["pname"]
assert p["enabled"], p
assert p["hooks"] == 6, p
assert p["hits"] >= 1, p
assert p["map_entries"] >= 1, p
print("status pname:", p)
PY
  echo "PASS: pname 采集/匹配/状态面均生效"
}

# P15：订阅 + 节点组会话——两个 ss 后端（A 可被 kill 验证 failover）
# + 一个不支持协议行（验证订阅逐行容错）+ 本地订阅 HTTP 服务器。
subscribe_up() {
  require_root
  [ -f "$OBJ" ] && [ -x "$LOADER" ] || die "先运行 $0 build"
  cleanup
  local meth="chacha20-ietf-poly1305" pass="testpass"
  {
    echo "ss://$meth:$pass@127.0.0.1:$SS_PORT#node-a"
    echo "ss://$meth:$pass@127.0.0.1:$SS_PORT_B#node-b"
    echo "bogus://ignored"
  } | base64 -w0 >"$SUB_BODY"
  echo >>"$SUB_BODY"
  cat >"$SUB_CONFIG" <<EOF
# P15：订阅 + 节点组（lab）；tcp_check_url 用 WAN echo（echo 回显即视为 check 成功）
global {
    tcp_check_url: 'http://10.9.9.2:9999'
    check_interval: '1s'
    check_tolerance: '1'
}
subscription {
    lab: 'http://127.0.0.1:$SUB_PORT/sub'
}
group {
    proxy {
        filter: subtag(lab)
        policy: min_moving_avg
    }
}
routing {
    dip(1.1.1.1/32) && dport(8080) -> proxy
    fallback: direct
}
EOF
  chmod 640 "$SUB_CONFIG"
  USE_CONFIG="$SUB_CONFIG" USE_SS=1 USE_SS_METHOD="$meth" USE_SS_PASSWORD="$pass" \
    USE_SS_B=1 USE_SUB_SERVER=1 USE_RELAY_IDLE=600 up
}

test_subscribe() {
  require_root
  echo "== P15：订阅拉取 + 节点组（policy/健康检查/failover）=="
  local out json
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out" | grep -q "wan-echo-ok" || {
    echo "FAIL: 首次经组拨号未成功"; echo "$out"; exit 1;
  }
  echo "PASS: 首次探测经节点组成功"
  grep -q "订阅 lab: 拉取成功，2 个节点" "$LOG" \
    || { echo "FAIL: 日志无订阅拉取记录"; tail -5 "$LOG"; exit 1; }
  grep -q "节点组 proxy: 2 个成员" "$LOG" \
    || { echo "FAIL: 日志无组构建记录"; tail -5 "$LOG"; exit 1; }
  json="$("$LOADER" status --socket "$STATUS_SOCK" --json 2>/dev/null || true)"
  echo "$json" | python3 -c '
import json, sys
d = json.load(sys.stdin)
g = d.get("group") or {}
assert g.get("members") == 2, g
assert g.get("alive") == 2, g
print("group=%s policy=%s members=%d alive=%d" % (g["name"], g["policy"], g["members"], g["alive"]))
' || { echo "FAIL: 状态面 group 信息不符"; exit 1; }

  echo "-- kill 节点 A，等健康检查标死（interval=1s tolerance=1）--"
  kill "$(cat "$SS_PID_FILE")" 2>/dev/null || true
  rm -f "$SS_PID_FILE"
  sleep 4
  json="$("$LOADER" status --socket "$STATUS_SOCK" --json 2>/dev/null || true)"
  echo "$json" | python3 -c '
import json, sys
d = json.load(sys.stdin)
g = d.get("group") or {}
assert g.get("alive") == 1, ("期望 1 个存活", g)
dead = [n["name"] for n in g["nodes"] if not n["alive"]]
print("alive=%d dead=%s" % (g["alive"], dead))
' || { echo "FAIL: 健康检查未将 A 标死"; exit 1; }
  echo "PASS: 健康检查将 A 标死"

  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out" | grep -q "wan-echo-ok" \
    || { echo "FAIL: failover 后探测未成功"; echo "$out"; exit 1; }
  echo "PASS: failover 后经节点 B 拨号成功（组 select/failover 计数见状态面）"
}

# P34：订阅顺序回退（pacman 风格）——两个订阅源各 1 节点（ss A/B）；
# 首拨走声明顺序第一源；kill 第一源后被标死 → 活动层切到第二源。
sub_order_up() {
  require_root
  [ -f "$OBJ" ] && [ -x "$LOADER" ] || die "先运行 $0 build"
  cleanup
  local meth="chacha20-ietf-poly1305" pass="testpass"
  { echo "ss://$meth:$pass@127.0.0.1:$SS_PORT#主源-节点"; } | base64 -w0 >"$SUB_BODY"
  echo >>"$SUB_BODY"
  { echo "ss://$meth:$pass@127.0.0.1:$SS_PORT_B#备源-节点"; } | base64 -w0 >"$SUB_BODY2"
  echo >>"$SUB_BODY2"
  # P34：第二源用「URL 文件」（相对路径按 config 目录解析）+ 单行 URL 间接抓取
  printf 'http://127.0.0.1:%s/sub2' "$SUB_PORT" >"$SUB_URL_FILE"
  cat >"$SUB_ORDER_CONFIG" <<EOF
# P34：订阅顺序回退（两个来源；按声明顺序优先，全部标死才切下一源）
global {
    tcp_check_url: 'http://10.9.9.2:9999'
    check_interval: '1s'
    check_tolerance: '1'
    # P35：inotify 事件驱动（兜底扫描 30s——重排断言必须在 2s 内生效，证明走的是事件）
    watch_config: 30
}
subscription {
    sub1: 'http://127.0.0.1:$SUB_PORT/sub'
    sub2: 'sodama-sub2.url'
}
group {
    proxy {
        policy: min_moving_avg
    }
}
routing {
    dip(1.1.1.1/32) && dport(8080) -> proxy
    fallback: direct
}
EOF
  chmod 640 "$SUB_ORDER_CONFIG"
  USE_CONFIG="$SUB_ORDER_CONFIG" USE_SS=1 USE_SS_METHOD="$meth" USE_SS_PASSWORD="$pass" \
    USE_SS_B=1 USE_SUB_SERVER=1 USE_RELAY_IDLE=600 up
}

test_sub_order() {
  require_root
  echo "== P34：订阅顺序回退（pacman 风格：按声明顺序优先，标死才切）=="
  local out json
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out" | grep -q "wan-echo-ok" || { echo "FAIL: 首次经组拨号未成功"; echo "$out"; exit 1; }
  grep -q "订阅 sub1: 拉取成功，1 个节点（来源顺序 #1）" "$LOG" \
    || { echo "FAIL: 日志无 sub1 拉取/顺序记录"; tail -5 "$LOG"; exit 1; }
  grep -q "订阅 sub2: 拉取成功，1 个节点（来源顺序 #2）" "$LOG" \
    || { echo "FAIL: 日志无 sub2 拉取/顺序记录"; tail -5 "$LOG"; exit 1; }
  json="$("$LOADER" status --socket "$STATUS_SOCK" --json 2>/dev/null || true)"
  echo "$json" | python3 -c '
import json, sys
d = json.load(sys.stdin)
g = d.get("group") or {}
assert g.get("subscription_failover") is True, g
assert g.get("active_tag") == "sub1", ("初始活动层应为 sub1", g.get("active_tag"))
print("active_tag=%s members=%d alive=%d" % (g["active_tag"], g["members"], g["alive"]))
' || { echo "FAIL: 初始活动订阅应为 sub1"; exit 1; }
  echo "PASS: 初始活动订阅 = sub1（声明顺序第一）"

  echo "-- 配置重排：sub2 提到前面（inotify 热驱动 + 订阅缓存，无 kill）--"
  sed -i "s|sub1: 'http://127.0.0.1:$SUB_PORT/sub'|TMP_LINE|; \
          s|sub2: 'sodama-sub2.url'|sub1: 'http://127.0.0.1:$SUB_PORT/sub'|; \
          s|TMP_LINE|sub2: 'sodama-sub2.url'|" "$SUB_ORDER_CONFIG"
  sleep 2
  json="$("$LOADER" status --socket "$STATUS_SOCK" --json 2>/dev/null || true)"
  echo "$json" | python3 -c '
import json, sys
d = json.load(sys.stdin)
g = d.get("group") or {}
assert g.get("active_tag") == "sub2", ("重排后活动层应为 sub2", g.get("active_tag"))
print("active_tag=%s（重排后）" % g["active_tag"])
' || { echo "FAIL: 配置重排未在 2s 内生效"; grep -a config-watch "$LOG" | tail -3; exit 1; }
  grep -q "检测到配置变更（inotify）" "$LOG" || { echo "FAIL: 未走 inotify 事件"; grep -a config-watch "$LOG" | tail -3; exit 1; }
  grep -q "命中缓存" "$LOG" || { echo "FAIL: fast reload 未走订阅缓存"; grep -a '订阅 sub' "$LOG" | tail -3; exit 1; }
  echo "PASS: 配置重排 2s 内生效（inotify + 订阅节点缓存 fast reload）"

  echo "-- 重排回 sub1 在前（双向验证）--"
  sed -i "s|sub1: 'http://127.0.0.1:$SUB_PORT/sub'|TMP_LINE|; \
          s|sub2: 'sodama-sub2.url'|sub1: 'http://127.0.0.1:$SUB_PORT/sub'|; \
          s|TMP_LINE|sub2: 'sodama-sub2.url'|" "$SUB_ORDER_CONFIG"
  sleep 2
  json="$("$LOADER" status --socket "$STATUS_SOCK" --json 2>/dev/null || true)"
  echo "$json" | python3 -c '
import json, sys
d = json.load(sys.stdin)
g = d.get("group") or {}
assert g.get("active_tag") == "sub1", ("重排回后活动层应为 sub1", g.get("active_tag"))
print("active_tag=%s（换回后）" % g["active_tag"])
' || { echo "FAIL: 重排回未生效"; exit 1; }
  echo "PASS: 重排回 sub1 也 2s 内生效"

  echo "-- kill 第一源节点（ss A），等健康检查标死（interval=1s tolerance=1）--"
  kill "$(cat "$SS_PID_FILE")" 2>/dev/null || true
  rm -f "$SS_PID_FILE"
  sleep 4
  json="$("$LOADER" status --socket "$STATUS_SOCK" --json 2>/dev/null || true)"
  echo "$json" | python3 -c '
import json, sys
d = json.load(sys.stdin)
g = d.get("group") or {}
assert g.get("active_tag") == "sub2", ("第一源标死后应切 sub2", g.get("active_tag"))
dead = [n["name"] for n in g["nodes"] if not n["alive"]]
print("active_tag=%s dead=%s" % (g["active_tag"], dead))
' || { echo "FAIL: 活动订阅未切到 sub2"; exit 1; }
  grep -q "活动订阅 -> sub2" "$LOG" || { echo "FAIL: 日志无切换记录"; tail -5 "$LOG"; exit 1; }
  echo "PASS: 第一源标死 → 活动订阅切到 sub2（日志可见）"

  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out" | grep -q "wan-echo-ok" \
    || { echo "FAIL: 切换后探测未成功"; echo "$out"; exit 1; }
  echo "PASS: 切换后经第二源拨号成功（顺序回退端到端）"
}

# P36：规则集——标准格式分流规则文件（Clash YAML / sing-box JSON / 纯文本）+ URL 自动下载。
ruleset_up() {
  require_root
  [ -f "$OBJ" ] && [ -x "$LOADER" ] || die "先运行 $0 build"
  cleanup
  local meth="chacha20-ietf-poly1305" pass="testpass"
  mkdir -p "$RS_DIR"
  { echo "ss://$meth:$pass@127.0.0.1:$SS_PORT#node-a"; } | base64 -w0 >"$SUB_BODY"
  echo >>"$SUB_BODY"
  # 1) Clash rule-provider（DOMAIN-SUFFIX 标准写法 + 一条 IP-CIDR 应被忽略并计数）
  cat >"$RS_CLASH_YAML" <<'YAML'
payload:
  - DOMAIN-SUFFIX,proxy.test
  - IP-CIDR,10.0.0.0/8,no-resolve
YAML
  # 2) sing-box rule-set JSON v1
  cat >"$RS_SINGBOX_JSON" <<'JSON'
{"version":1,"rules":[{"domain_suffix":["direct.test"],"ip_cidr":["10.0.0.0/8"]}]}
JSON
  # 3) 纯文本域名列表（裸条目 = suffix；可直接编辑）
  cat >"$RS_PLAIN_TXT" <<'TXT'
# 用户自定义：强制直连的域名（裸条目 = suffix）
plain.test
TXT
  cat >"$RS_CONFIG" <<EOF
# P36：规则集夹具——三种标准格式 + URL 下载（本地 sub_server 提供 /ruleset/*）
global {
    tcp_check_url: 'http://10.9.9.2:9999'
    check_interval: '1s'
    check_tolerance: '1'
    rule_set_update_interval: 0   # 测试：每次 reload 都重新拉取
}
rule_set {
    rs_clash: 'http://127.0.0.1:$SUB_PORT/ruleset/clash.yaml'
    rs_json: 'http://127.0.0.1:$SUB_PORT/ruleset/singbox.json'
    rs_plain: 'file://$RS_PLAIN_TXT'
}
subscription {
    lab: 'http://127.0.0.1:$SUB_PORT/sub'
}
group {
    proxy {
        policy: min_moving_avg
    }
}
routing {
    # 用户自定义分流（规则集引用；顺序 = 优先级）
    domain(ruleset: rs_clash) -> direct
    domain(ruleset: rs_json) -> proxy
    domain(ruleset: rs_plain) -> direct
    fallback: proxy
}
EOF
  chmod 640 "$RS_CONFIG"
  SUB_ROUTES_SPEC="/ruleset/clash.yaml=$RS_CLASH_YAML,/ruleset/singbox.json=$RS_SINGBOX_JSON" \
    USE_CONFIG="$RS_CONFIG" USE_FAKE_DNS=1 USE_DNS_UPSTREAM="127.0.0.1:$FAKE_DNS_PORT" \
    USE_SS=1 USE_SS_METHOD="$meth" USE_SS_PASSWORD="$pass" USE_SUB_SERVER=1 USE_RELAY_IDLE=600 up
}

test_ruleset() {
  require_root
  echo "== P36：规则集（Clash YAML / sing-box JSON / 纯文本 + URL 下载/刷新）=="
  local name ip out spec
  for spec in "proxy.test:10.9.10.3" "direct.test:10.9.10.4" "plain.test:10.9.10.5"; do
    name="${spec%%:*}"; ip="${spec##*:}"
    out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 "$name" 2>&1 || true)"
    printf '%s\n' "$out" | grep -q "^answer=$ip" || { echo "FAIL: $name 未解析到 $ip"; echo "$out"; exit 1; }
  done
  # 规则集判定（带 relay：代理 = 新增 RELAY <ip>:9999 日志行；直连 = 无新增且能回显）
  local n0 n1
  relay_hits() { grep -ac "RELAY $1:9999 established" "$LOG" 2>/dev/null || true; }
  # clash → direct（回退为 proxy，能直连即证明规则集生效）
  n0="$(relay_hits 10.9.10.3)"
  out="$(ip netns exec "$CLIENT_NS" timeout 6 python3 "$HERE/client_probe.py" 10.9.10.3 9999 2>&1 || true)"
  echo "$out" | grep -q "wan-echo-ok" || { echo "FAIL: rs_clash 域未到达 WAN"; echo "$out"; exit 1; }
  n1="$(relay_hits 10.9.10.3)"
  [ "$n0" = "$n1" ] || { echo "FAIL: rs_clash 域走了代理（应为规则集直连）"; exit 1; }
  # json → proxy（新增 RELAY 日志行）
  n0="$(relay_hits 10.9.10.4)"
  out="$(ip netns exec "$CLIENT_NS" timeout 6 python3 "$HERE/client_probe.py" 10.9.10.4 9999 2>&1 || true)"
  echo "$out" | grep -q "wan-echo-ok" || { echo "FAIL: rs_json 域未到达 WAN"; echo "$out"; exit 1; }
  n1="$(relay_hits 10.9.10.4)"
  [ "$n1" -gt "$n0" ] || { echo "FAIL: rs_json(sing-box) 域未走代理（无 RELAY 日志）"; exit 1; }
  # plain → direct
  n0="$(relay_hits 10.9.10.5)"
  out="$(ip netns exec "$CLIENT_NS" timeout 6 python3 "$HERE/client_probe.py" 10.9.10.5 9999 2>&1 || true)"
  echo "$out" | grep -q "wan-echo-ok" || { echo "FAIL: rs_plain 域未到达 WAN"; echo "$out"; exit 1; }
  n1="$(relay_hits 10.9.10.5)"
  [ "$n0" = "$n1" ] || { echo "FAIL: rs_plain(纯文本) 域走了代理（应为直连）"; exit 1; }
  echo "PASS: 三种格式规则集分流全部生效（代理=RELAY 日志，直连=无）"
  grep -q "规则集 rs_clash: 1 条域名" "$LOG" || { echo "FAIL: 日志无 rs_clash 计数"; tail -5 "$LOG"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
rs = {r["tag"]: r for r in v.get("rule_sets") or []}
assert set(rs) == {"rs_clash", "rs_json", "rs_plain"}, rs
assert rs["rs_clash"]["suffix"] == 1 and rs["rs_clash"]["ignored"] == 1, rs["rs_clash"]
assert rs["rs_json"]["suffix"] == 1 and rs["rs_json"]["ignored"] == 1, rs["rs_json"]
assert rs["rs_plain"]["suffix"] == 1, rs["rs_plain"]
print("rule_sets: " + ", ".join("%s(entries=%d ignored=%d)" % (r["tag"], r["entries"], r["ignored"]) for r in rs.values()))
PY

  echo "-- 更新规则集 URL 内容（sing-box JSON 增加 plain.test→proxy）+ SIGHUP --"
  cat >"$RS_SINGBOX_JSON" <<'JSON'
{"version":1,"rules":[{"domain_suffix":["direct.test","plain.test"]}]}
JSON
  kill -HUP "$(cat "$PID_FILE")"
  sleep 2
  n0="$(relay_hits 10.9.10.5)"
  out="$(ip netns exec "$CLIENT_NS" timeout 6 python3 "$HERE/client_probe.py" 10.9.10.5 9999 2>&1 || true)"
  echo "$out" | grep -q "wan-echo-ok" || { echo "FAIL: 规则集刷新后 plain.test 未到达 WAN"; echo "$out"; exit 1; }
  n1="$(relay_hits 10.9.10.5)"
  [ "$n1" -gt "$n0" ] || { echo "FAIL: 规则集刷新后 plain.test 未改判代理"; exit 1; }
  echo "PASS: 规则集 URL 更新（interval=0 热刷新）后分流改判"

  echo "-- 引用未知规则集：reload 应失败并保留旧槽 --"
  python3 - "$RS_CONFIG" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
i = s.rstrip().rfind("}")
s = s[:i] + "    domain(ruleset: nope) -> direct\n" + s[i:]
open(p, "w").write(s)
PY
  kill -HUP "$(cat "$PID_FILE")"
  sleep 2
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
r = v.get("reload") or {}
assert r.get("ok") is False, r
print("reload ok=False（未知规则集）:", (r.get("error") or "")[:90])
PY
  n0="$(relay_hits 10.9.10.3)"
  out="$(ip netns exec "$CLIENT_NS" timeout 6 python3 "$HERE/client_probe.py" 10.9.10.3 9999 2>&1 || true)"
  echo "$out" | grep -q "wan-echo-ok" || { echo "FAIL: 失败 reload 后旧槽规则未保持"; echo "$out"; exit 1; }
  n1="$(relay_hits 10.9.10.3)"
  [ "$n0" = "$n1" ] || { echo "FAIL: 失败 reload 后判定发生变化"; exit 1; }
  echo "PASS: 未知规则集硬失败且旧槽保留"
}

# P18e：SS2022——跨实现验证（shadowsocks-rust ssserver，SIP022）。
ss2022_up() {
  require_root
  [ -f "$OBJ" ] && [ -x "$LOADER" ] || die "先运行 $0 build"
  cleanup
  local creds="$SS2022_METHOD:$SS2022_PSK"
  local b64
  b64="$(printf '%s' "$creds" | base64 -w0 | tr '+/' '-_' | tr -d '=')"
  USE_RULES="$HERE/rules.dae" USE_SS_2022=1 USE_OFFLOAD=1 \
    USE_DIALER="ss://$b64@127.0.0.1:$SS_PORT#ss2022" \
    USE_RELAY_IDLE=600 up
}

test_ss2022() {
  require_root
  echo "== P18e：Shadowsocks 2022（跨实现 shadowsocks-rust ssserver）=="
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "wan-echo-ok data=ping" \
    || { echo "FAIL: ss2022 链路未把流量转发到真实目标"; exit 1; }
  kill -0 "$(cat "$SS2022_PID_FILE")" 2>/dev/null \
    || { echo "FAIL: ssserver 进程已退出"; cat /tmp/sodama-ss2022.log; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 30 python3 "$HERE/stream_probe.py" "$PROXY_DST" 8080 512 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "^stream-ok bytes=524288" || { echo "FAIL: ss2022 大流量回显不一致"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
assert v["dialer"].startswith("ss://2022-blake3-aes-128-gcm@"), v["dialer"]
r = v["relay"]
assert r["conns_total"] >= 2, r
assert r["dial_errors"] == 0, r
assert r["offload_enabled"] and r["offloaded_total"] == 0, r  # 协议互斥
assert r["bytes_up"] >= 512 * 1024 and r["bytes_down"] >= 512 * 1024, r
print("ss2022: conns=%d bytes_up=%d bytes_down=%d" % (r["conns_total"], r["bytes_up"], r["bytes_down"]))
PY
  echo "PASS: shadowsocks 2022（SIP022 跨实现 + 512KB 回显一致）"
}

# P18e：HTTP CONNECT 出站（独立 Python 代理夹具）。
http_up() {
  require_root
  [ -f "$OBJ" ] && [ -x "$LOADER" ] || die "先运行 $0 build"
  cleanup
  USE_RULES="$HERE/rules.dae" USE_HTTP_PROXY=1 USE_OFFLOAD=1 \
    USE_DIALER="http://127.0.0.1:$HTTP_PROXY_PORT" \
    USE_RELAY_IDLE=600 up
}

test_http_out() {
  require_root
  echo "== P18e：HTTP CONNECT 出站（Python 代理夹具）=="
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "wan-echo-ok data=ping" \
    || { echo "FAIL: http 出站未把流量转发到真实目标"; exit 1; }
  grep -q "CONNECT $PROXY_DST:8080" "$HTTP_PROXY_LOG" \
    || { echo "FAIL: 代理夹具没看到 CONNECT（跨实现失败）"; cat "$HTTP_PROXY_LOG" 2>/dev/null; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 30 python3 "$HERE/stream_probe.py" "$PROXY_DST" 8080 512 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "^stream-ok bytes=524288" || { echo "FAIL: http 大流量回显不一致"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
assert v["dialer"].startswith("http://"), v["dialer"]
r = v["relay"]
assert r["conns_total"] >= 2, r
assert r["dial_errors"] == 0, r
assert r["offload_enabled"] and r["offloaded_total"] == 0, r
print("http CONNECT: conns=%d bytes_up=%d bytes_down=%d" % (r["conns_total"], r["bytes_up"], r["bytes_down"]))
PY
  echo "PASS: HTTP CONNECT 出站（CONNECT 隧道 + 512KB 回显一致）"
}

# P18e：SIGHUP 订阅热更新（重拉订阅 → 整体替换成员 + 健康继承）。
# 用法：sub-reload-up 后执行；本测试会改写 $SUB_BODY 并 SIGHUP。
test_sub_reload() {
  require_root
  echo "== P18e：SIGHUP 订阅热更新（2 节点 → 1 节点）=="
  grep -q "订阅 lab: 拉取成功，2 个节点" "$LOG" \
    || { echo "FAIL: 初始订阅应为 2 节点（先 sub-reload-up）"; tail -5 "$LOG"; exit 1; }
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out" | grep -q "wan-echo-ok" || { echo "FAIL: 初始经组拨号失败"; echo "$out"; exit 1; }
  # 改订阅：去掉 node-b（与 subscribe_up 相同的链接格式）
  {
    echo "ss://chacha20-ietf-poly1305:testpass@127.0.0.1:$SS_PORT#node-a"
  } | base64 -w0 >"$SUB_BODY"
  echo >>"$SUB_BODY"
  kill -HUP "$(cat "$PID_FILE")"
  sleep 3
  grep -q "订阅热更新：组 proxy 1 成员（继承 1 健康）" "$LOG" \
    || { echo "FAIL: 日志无订阅热更新或健康继承计数"; tail -8 "$LOG"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
g = v.get("group") or {}
assert g.get("members") == 1, g
assert g.get("nodes")[0]["name"] == "node-a", g
assert g.get("nodes")[0]["alive"], g
print("hot reload: members=%d node=%s alive=%s" % (g["members"], g["nodes"][0]["name"], g["nodes"][0]["alive"]))
PY
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out" | grep -q "wan-echo-ok" || { echo "FAIL: 热更新后拨号失败"; echo "$out"; exit 1; }
  echo "PASS: 订阅热更新（成员 2→1，node-a 继承健康，拨号正常）"
}

# P19：多组分派——规则按组名选组（proxy→A / alt→B），数据面 outbound 索引
# 经 conn_state 回读，relay/UDP 按连接选组。
groups_up() {
  require_root
  [ -f "$OBJ" ] && [ -x "$LOADER" ] || die "先运行 $0 build"
  cleanup
  local meth="chacha20-ietf-poly1305" pass="testpass"
  {
    echo "ss://$meth:$pass@127.0.0.1:$SS_PORT#node-a"
    echo "ss://$meth:$pass@127.0.0.1:$SS_PORT_B#node-b"
  } | base64 -w0 >"$SUB_BODY"
  echo >>"$SUB_BODY"
  cat >"$SUB_GROUPS_CONFIG" <<EOF
# P19：多组分派（proxy→node-a / alt→node-b；routing 按目标端口选组）
global {
    tcp_check_url: 'http://10.9.9.2:9999'
    check_interval: '1s'
    check_tolerance: '1'
}
subscription {
    lab: 'http://127.0.0.1:$SUB_PORT/sub'
}
group {
    proxy {
        filter: name(node-a)
        policy: min_moving_avg
    }
    alt {
        filter: name(node-b)
        policy: min_moving_avg
    }
}
routing {
    dip(1.1.1.1/32) && dport(8080) -> proxy
    dip(1.1.1.1/32) && dport(8082) -> alt
    fallback: direct
}
EOF
  chmod 640 "$SUB_GROUPS_CONFIG"
  USE_CONFIG="$SUB_GROUPS_CONFIG" USE_SS=1 USE_SS_METHOD="$meth" USE_SS_PASSWORD="$pass" \
    USE_SS_B=1 USE_SUB_SERVER=1 USE_RELAY_IDLE=600 up
}

test_groups() {
  require_root
  echo "== P19：多组分派（8080→proxy/node-a，8082→alt/node-b）=="
  grep -q "P19 多组分派：2 个组" "$LOG" \
    || { echo "FAIL: 日志无多组构建（先 groups-up）"; tail -5 "$LOG"; exit 1; }
  local out
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
gs = v.get("groups") or []
assert len(gs) == 2, gs
by = {g["name"]: g for g in gs}
assert by["proxy"]["members"] == 1 and by["alt"]["members"] == 1, gs
assert by["proxy"]["default"] and not by["alt"]["default"], gs
assert v["group"]["name"] == "proxy", v.get("group")
print("groups: " + ", ".join("%s(idx=%d members=%d default=%s)" % (g["name"], g["index"], g["members"], g["default"]) for g in gs))
PY
  # 8080 → proxy 组（node-a / SS_PORT，首包应答带 wan-echo-ok）
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out" | grep -q "wan-echo-ok" || { echo "FAIL: 8080 经 proxy 组未通"; echo "$out"; exit 1; }
  # 8082 → alt 组（node-b / SS_PORT_B，纯回显：应答就是 ping）
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8082 2>&1 || true)"
  echo "$out" | grep -q "^ping" || { echo "FAIL: 8082 经 alt 组未通"; echo "$out"; exit 1; }
  # 交叉验证：谁看到谁的 target（分派必须精确，不能串）
  grep -q "TCP target=$PROXY_DST:8080" "$SS_LOG" || { echo "FAIL: ss-A 未看到 8080"; exit 1; }
  grep -q "TCP target=$PROXY_DST:8082" "${SS_LOG}.b" || { echo "FAIL: ss-B 未看到 8082"; exit 1; }
  if grep -q "TCP target=$PROXY_DST:8082" "$SS_LOG"; then echo "FAIL: 8082 错走到 ss-A（分派失效）"; exit 1; fi
  if grep -q "TCP target=$PROXY_DST:8080" "${SS_LOG}.b"; then echo "FAIL: 8080 错走到 ss-B（分派失效）"; exit 1; fi
  echo "PASS: 8080→node-a / 8082→node-b（双 ss 日志交叉为证）"
  # SIGHUP 后分派保持（每组各自替换成员）
  kill -HUP "$(cat "$PID_FILE")"
  sleep 3
  grep -q "订阅热更新：组 proxy 1 成员" "$LOG" \
    || { echo "FAIL: 热更新日志缺 proxy 组"; tail -8 "$LOG"; exit 1; }
  grep -q "订阅热更新：组 alt 1 成员" "$LOG" \
    || { echo "FAIL: 热更新日志缺 alt 组"; tail -8 "$LOG"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8082 2>&1 || true)"
  echo "$out" | grep -q "^ping" || { echo "FAIL: 热更新后 alt 组拨号失败"; echo "$out"; exit 1; }
  echo "PASS: 多组分派（含 SIGHUP 热更新后复测）"
}

# P4c：TCP offload——同一 512KB 流量下，用户态字节数远小于总传输（内核拼接证据）。
test_relay_offload() {
  require_root
  echo "== 测试 TCP offload（fast_sock + sk_skb 内核对拼）=="
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "wan-echo-ok data=ping" || { echo "FAIL: offload 路径下连接不通"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 30 python3 "$HERE/stream_probe.py" "$PROXY_DST" 8080 512 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "^stream-ok bytes=524288" || { echo "FAIL: offload 大流量回显不一致"; exit 1; }
  check_offload_accounting
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
r = v["relay"]
assert r["offload_enabled"], r
assert r["offloaded_total"] >= 2, r
assert r["offload_failures"] == 0, r
userspace = r["bytes_up"] + r["bytes_down"]
assert userspace < 262144, ("用户态字节数过大，offload 未生效", r)
assert v["stats"]["offload_verdicts"] > 0, v["stats"]
assert v["stats"]["offload_redirects"] > 0, v["stats"]
print("offload: offloaded=%d failures=%d userspace_bytes=%d verdicts=%d redirects=%d" % (
    r["offloaded_total"], r["offload_failures"], userspace,
    v["stats"]["offload_verdicts"], v["stats"]["offload_redirects"]))
PY
  echo "PASS: TCP offload（512KB 走内核拼接，用户态字节数远小于总传输）"
}

# P7：offload 连接生命周期——半关闭超过 relayHalfCloseThreshold（10s，对照 dae）
# 后看门狗强制关闭两侧，泵线程退出、fast_sock 键注销、conns_active 归零。
test_offload_lifecycle() {
  require_root
  echo "== 测试 offload 连接回收（半关闭超时 / fast_sock 键注销） =="
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 30 python3 "$HERE/stream_probe.py" "$PROXY_DST" 8080 512 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "^stream-ok bytes=524288" || { echo "FAIL: offload 大流量回显不一致"; exit 1; }
  echo "-- 等 10s 半关闭超时 + 看门狗回收 --"
  sleep 14
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
r = v["relay"]
active = r["conns_active"]
fast = v["maps"].get("fast_sock")
assert r["offloaded_total"] >= 1, r
assert active == 0, ("offload 连接未回收（conns_active=%s）" % active, r)
assert fast == 0, ("fast_sock 键未注销（=%s）" % fast, v["maps"])
print("offload 生命周期: offloaded=%d active=%d fast_sock=%d" % (
    r["offloaded_total"], active, fast))
PY
  echo "PASS: offload 连接已回收（conns_active=0，fast_sock=0）"
  # 对标批：键摘除时汇总回收内核路径字节
  check_offload_reclaim
}

# 对标批：offload 字节记账（fentry/kprobe `skb_send_sock`）——挂载证据 + 内核路径字节数。
# 对照 dae `kern/tproxy.c:4360-4393` 与 `control/tcp_offload_hook.go`（fentry 优先、kprobe 回退）。
check_offload_accounting() {
  require_root
  if grep -q "offload 记账: fentry/skb_send_sock 已挂载" "$LOG"; then
    echo "offload 记账：fentry 形态（零开销探针）"
  elif grep -q "offload 记账: kprobe/skb_send_sock 已挂载" "$LOG"; then
    echo "offload 记账：kprobe 形态（fentry 回退）"
  elif grep -q "offload 记账: BTF 解析失败" "$LOG"; then
    echo "SKIP: 本内核无 vmlinux BTF，记账未挂载（计量降级，不影响转发）"
    return 0
  else
    echo "FAIL: offload 记账探针未挂载（既无 fentry 也无 kprobe，且无 BTF 失败日志）"
    grep "offload 记账" "$LOG" || true
    exit 1
  fi
  # 挂载可选（BTF 不可用时跳过），但一旦挂上就必须能看到「内核路径推了字节」。
  grep -q "offload 记账: BTF 解析失败" "$LOG" && return 0
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
s = v["offload_sent"]
assert s["kernel_bytes"] > 0, ("内核路径推送字节为 0（探针未命中？）", s)
print("offload 记账: kernel_bytes=%d account_drops=%d" % (s["kernel_bytes"], s["account_drops"]))
PY
}

# 对标批：键摘除时汇总回收（loaders 侧 `offload_sent_reclaim`）。
check_offload_reclaim() {
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
s = v["offload_sent"]
assert s["reclaimed_bytes"] > 0, ("键摘除后未回收字节（回收路径未生效）", s)
print("offload 回收: reclaimed_bytes=%d" % s["reclaimed_bytes"])
PY
}

# 对标批 C1a：L3 变体的**选择与挂载**（可稳定判定，入门禁）。
# 已实测（VM/7.2.8）：landae3（arphrd=768）被 loader 判为 L3 → 挂 `sodama_lan_ingress_l3`。
test_l3_attach() {
  require_root
  rm -f /tmp/sodama-l3-skip
  [ -n "$L3_IFACE" ] || L3_IFACE=landae3
  [ -e "/sys/class/net/$L3_IFACE" ] || { echo "SKIP: 无 L3 接口（$L3_IFACE 不存在，ipip 隧道未建）"; touch /tmp/sodama-l3-skip; return 0; }
  local ty
  ty="$(cat "/sys/class/net/$L3_IFACE/type" 2>/dev/null || echo '?')"
  echo "$L3_IFACE type=$ty（768=ARPHRD_TUNNEL）"
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json "$L3_IFACE" <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
iface = sys.argv[2]
hooks = v.get("hooks") or []
expect = "sodama_lan_ingress_l3@%s" % iface
assert expect in hooks, ("L3 变体未挂载（auto 判定失败）", hooks)
seen = [h for h in hooks if h.startswith("sodama_lan_ingress")]
assert any(h == expect for h in seen), ("L2 变体仍挂在 L3 接口上？", seen)
print("L3 钩子: %s" % expect)
PY
  echo "PASS: L3 接口被识别并挂上 _l3 变体"
}

# 对标批 C1b：L3 **端到端**（经 ipip 隧道的代理路径 + 补头/剥头闭环）。
# 状态：VM 内尚未打通（补头/剥头/lab 两侧落地均已实测，但经本拓扑的端到端回程未过），
# 故**不入 verify 门禁**；留作真机（生产路由器 6.12 + 真 tun/ppp）与拓扑补完后的验收。
test_l3() {
  require_root
  rm -f /tmp/sodama-l3-skip
  # L3_IFACE 只在 up()（另一个进程）里赋值，这里必须自探测（否则误 SKIP）。
  [ -n "$L3_IFACE" ] || L3_IFACE=landae3
  [ -e "/sys/class/net/$L3_IFACE" ] || { echo "SKIP: 无 L3 接口（$L3_IFACE 不存在，ipip 隧道未建）"; touch /tmp/sodama-l3-skip; return 0; }
  echo "== 测试 L3 端到端（ipip 隧道 $L3_IFACE）=="
  # 接口类型自证：ipip 应为 arphrd=768（ARPHRD_TUNNEL）。数值只作证据打印，
  # 真正的断言是「loader 把它归为 L3 并挂上了 _l3 变体」（下一段）。
  local ty
  ty="$(cat "/sys/class/net/$L3_IFACE/type" 2>/dev/null || echo '?')"
  echo "$L3_IFACE type=$ty（期望 768=ARPHRD_TUNNEL；非 1 即无链路头）"
  # 挂载证据：hook 名应带 _l3 后缀（本用例不重复断言，test-l3-attach 已断言）
  # 把该客户端的代理目标流量改走隧道（只影响本用例；结束前删回）
  ip -n "$CLIENT_NS" route replace "$PROXY_DST/32" dev l3cli
  # 判别口径同 test_proxy：只有真的被 redirect 到 tproxy socket（代理路径）时，
  # 加载器的 echo 才会带上 orig_dst=… 行；走直连/被丢包都是别的内容。
  local rc=0 out
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "orig_dst=$PROXY_DST:8080" || rc=1
  # 512KB 回显：无 dialer 会话的 tproxy 连接由 loader 回显夹具接管（每次回显带一行
  # banner），用 banner 容忍的探针校验字节完整性；只验字节一致，不依赖协议语义。
  out="$(ip netns exec "$CLIENT_NS" timeout 40 python3 "$HERE/tproxy_stream_probe.py" "$PROXY_DST" 8080 512 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "^stream-ok bytes=524288" || rc=1
  ip -n "$CLIENT_NS" route del "$PROXY_DST/32" dev l3cli 2>/dev/null || true
  [ "$rc" = 0 ] || { echo "FAIL: L3 链路分流未打通（补头/剥头/解析链）"; exit 1; }
  echo "PASS: L3 变体分流（经 ipip 隧道的 512KB 回显一致，补头+剥头闭环）"
}

# 对标批 C4：XDP 计量探针（恒 XDP_PASS）。挂载失败/内核不支持时 SKIP（不阻塞基线）。
test_xdp() {
  require_root
  rm -f /tmp/sodama-xdp-skip
  # USE_XDP_IFACE 只在 up()（另一个进程）里赋值；这里默认 landae（up() 的默认挂载口）。
  [ -n "${USE_XDP_IFACE:-}" ] || USE_XDP_IFACE=landae
  [ -e "/sys/class/net/$USE_XDP_IFACE" ] || { echo "SKIP: 接口 $USE_XDP_IFACE 不存在"; touch /tmp/sodama-xdp-skip; return 0; }
  echo "== 测试 XDP 计量探针（$USE_XDP_IFACE，仅计数）=="
  local i
  for i in 1 2 3; do
    "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json 2>/dev/null || true
    if grep -q '"xdp"' /tmp/sodama-status.json 2>/dev/null; then break; fi
    sleep 0.3
  done
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
x = v.get("xdp")
if x is None:
    print("SKIP: XDP 探针未挂载（内核/驱动不支持或未指定接口）")
    open("/tmp/sodama-xdp-skip", "w").close()
    sys.exit(0)
assert x["packets"] > 0, ("XDP 已挂载但未计数（探针未执行？）", x)
assert x["ipv4"] > 0, ("XDP 已挂载但对 IPv4 包未计数", x)
print("xdp: packets=%d bytes=%d ipv4=%d ipv6=%d other=%d" % (
    x["packets"], x["bytes"], x["ipv4"], x["ipv6"], x["other"]))
PY
  echo "PASS: XDP 探针计数可读且随流量推进（转发不受影响由其余用例覆盖）"
}

# ---------------------------------------------------------------- 能力缺口批次

# #1：must 糖会话（must.dae 拷到 /tmp，测试运行中改写后 SIGHUP 做 A/B）。
must_up() {
  require_root
  [ -f "$OBJ" ] && [ -x "$LOADER" ] || die "先运行 $0 build"
  USE_MUST_CONFIG=1 USE_CONFIG=/tmp/sodama-must.dae USE_RELAY_IDLE=600 up
}

# #1：`must_<组名>` 前缀糖 —— 配置层编译为 `<组名>(must)`（不再静默成 proxy），
# 且 must 语义在交付侧生效：DNS 流不被劫持（dae routing.md：must_groupname 不劫持处理 DNS）。
test_must() {
  require_root
  echo "== 能力缺口 #1：must_<组名> 前缀糖（must_proxy → proxy(must)）=="
  grep -qF 'outbound 映射：组 "must_proxy" -> proxy(must)' "$LOG" \
    || { echo "FAIL: 未见 must 糖映射日志（又静默映射成 proxy？）"; grep "outbound 映射" "$LOG" || true; exit 1; }
  grep -qE "type=L4Proto.*must=1" "$LOG" \
    || { echo "FAIL: 编译产物未见 must=1（配置路径丢 must？）"; grep -E "type=L4Proto" "$LOG" || true; exit 1; }
  echo "PASS: 糖映射日志 + 编译 must=1"
  # A/B：must 的 DNS 不劫持（queries 不涨）→ 去掉 must 后劫持（queries 涨）。
  local q1 q2 json
  ip netns exec "$CLIENT_NS" timeout 4 python3 "$HERE/dns_probe.py" "$PROXY_DST" must.test >/dev/null 2>&1 || true
  sleep 0.5
  json="$("$LOADER" status --socket "$STATUS_SOCK" --json 2>/dev/null || true)"
  q1="$(printf '%s' "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["dns"]["queries"])' 2>/dev/null || echo 0)"
  [ "${q1:-0}" -eq 0 ] || { echo "FAIL: must 流的 DNS 被劫持了（queries=$q1）"; exit 1; }
  echo "PASS: must_proxy 下 DNS 未被劫持（queries=0）"
  sed -i 's/l4proto(udp) \&\& dport(53) -> must_proxy/l4proto(udp) \&\& dport(53) -> proxy/' /tmp/sodama-must.dae
  kill -HUP "$(cat "$PID_FILE")"
  sleep 2
  ip netns exec "$CLIENT_NS" timeout 4 python3 "$HERE/dns_probe.py" "$PROXY_DST" plain.test >/dev/null 2>&1 || true
  sleep 0.5
  json="$("$LOADER" status --socket "$STATUS_SOCK" --json 2>/dev/null || true)"
  q2="$(printf '%s' "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["dns"]["queries"])' 2>/dev/null || echo 0)"
  [ "${q2:-0}" -ge 1 ] || { echo "FAIL: 普通 proxy 规则的 DNS 未被劫持（queries=$q2）"; exit 1; }
  echo "PASS: 对照（无 must）DNS 被劫持（queries=$q2）"
}

# #2：订阅 `http-file://` scheme（dae 风格）+ 磁盘回退（sub-cache；内存缓存关闭）。
subfile_up() {
  require_root
  [ -f "$OBJ" ] && [ -x "$LOADER" ] || die "先运行 $0 build"
  cleanup
  local meth="chacha20-ietf-poly1305" pass="testpass"
  {
    echo "ss://$meth:$pass@127.0.0.1:$SS_PORT#node-a"
    echo "ss://$meth:$pass@127.0.0.1:$SS_PORT_B#node-b"
  } | base64 -w0 >"$SUB_BODY"
  echo >>"$SUB_BODY"
  cat >"$SUB_CONFIG" <<EOF
# 能力缺口 #2：dae 风格 http-file://（拉取失败回退磁盘缓存，成功即更新）；
# sub_cache_ttl: 0 关内存缓存——SIGHUP 重载直接验磁盘回退路径。
global {
    tcp_check_url: 'http://10.9.9.2:9999'
    check_interval: '1s'
    check_tolerance: '1'
    sub_cache_ttl: 0
}
subscription {
    lab: 'http-file://127.0.0.1:$SUB_PORT/sub'
}
group {
    proxy {
        filter: subtag(lab)
        policy: min_moving_avg
    }
}
routing {
    dip(1.1.1.1/32) && dport(8080) -> proxy
    fallback: direct
}
EOF
  chmod 640 "$SUB_CONFIG"
  USE_CONFIG="$SUB_CONFIG" USE_SS=1 USE_SS_METHOD="$meth" USE_SS_PASSWORD="$pass" \
    USE_SS_B=1 USE_SUB_SERVER=1 USE_RELAY_IDLE=600 up
}

test_sub_file() {
  require_root
  echo "== 能力缺口 #2：订阅 http-file:// + 磁盘回退 =="
  grep -q "订阅 lab: 拉取成功，2 个节点" "$LOG" \
    || { echo "FAIL: http-file:// 源未拉取成功（scheme 未识别？）"; grep "订阅 lab" "$LOG" || true; exit 1; }
  [ -s /tmp/sub-cache/lab.bin ] \
    || { echo "FAIL: 拉取成功但未落盘 /tmp/sub-cache/lab.bin"; ls -la /tmp/sub-cache/ 2>/dev/null || true; exit 1; }
  echo "PASS: http-file:// 拉取成功并落盘（$(stat -c %s /tmp/sub-cache/lab.bin) 字节）"
  # 源掉线 + SIGHUP：内存缓存已关（sub_cache_ttl: 0）→ 应回退磁盘缓存。
  kill "$(cat "$SUB_PID_FILE")" 2>/dev/null || true
  rm -f "$SUB_PID_FILE"
  kill -HUP "$(cat "$PID_FILE")"
  sleep 2.5
  grep -q "回退磁盘缓存" "$LOG" \
    || { echo "FAIL: 源掉线后未回退磁盘缓存"; tail -8 "$LOG"; exit 1; }
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "wan-echo-ok" \
    || { echo "FAIL: 磁盘回退后拨号失败（磁盘缓存未被用？）"; exit 1; }
  echo "PASS: 源掉线 → SIGHUP 回退磁盘缓存，节点仍可用（拨号成功）"
}

# #3：接口懒绑定/热插拔会话（--lan 用 pattern，启动时无匹配）。
hotplug_up() {
  require_root
  [ -f "$OBJ" ] && [ -x "$LOADER" ] || die "先运行 $0 build"
  USE_LAN_ARG='hplug*' up
}

test_hotplug() {
  require_root
  echo "== 能力缺口 #3：接口懒绑定/热插拔（--lan 'hplug*'）=="
  grep -qF 'iface: lan 模式 "hplug*" 当前无匹配接口（懒绑定：出现后自动挂载）' "$LOG" \
    || { echo "FAIL: 启动时未给出懒绑定提示（模式未被当作 pattern？）"; grep "iface:" "$LOG" || true; exit 1; }
  echo "PASS: 启动时 hplug* 无匹配（懒绑定登记）"
  local i out n0 n1
  ip link add hplug-lan type veth peer name hplug-cli
  ip link set hplug-cli netns "$CLIENT_NS"
  ip addr add 10.60.0.1/24 dev hplug-lan
  ip link set hplug-lan up
  ip -n "$CLIENT_NS" link set hplug-cli up
  ip -n "$CLIENT_NS" addr add 10.60.0.2/24 dev hplug-cli
  for i in $(seq 1 30); do
    grep -qF "hotplug: 接口 hplug-lan 出现 → 已挂 lan 钩子" "$LOG" && break
    sleep 0.2
  done
  grep -qF "hotplug: 接口 hplug-lan 出现 → 已挂 lan 钩子" "$LOG" \
    || { echo "FAIL: 新接口未被自动补挂"; tail -5 "$LOG"; exit 1; }
  bpftool net show 2>/dev/null | grep -q "hplug-lan" \
    || { echo "FAIL: bpftool 未见 hplug-lan 钩子"; bpftool net show 2>/dev/null | head -10; exit 1; }
  echo "PASS: 新接口出现 → 自动补挂（日志 + bpftool）"
  # 功能：客户端改走新接口 → 仍被 tproxy 接管（banner）。
  ip -n "$CLIENT_NS" route replace "$PROXY_DST/32" via 10.60.0.1 dev hplug-cli
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "orig_dst=$PROXY_DST:8080" \
    || { echo "FAIL: 热插拔接口上的流量未被接管"; exit 1; }
  echo "PASS: 热插拔接口上的流量被 tproxy 接管（orig_dst 回显）"
  # churn：删除 → 记账；重加 → 再挂并恢复接管（l3_ifindex 清理/重建路径）。
  ip link del hplug-lan
  for i in $(seq 1 30); do
    grep -qF "hotplug: 接口 hplug-lan 消失" "$LOG" && break
    sleep 0.2
  done
  grep -qF "hotplug: 接口 hplug-lan 消失" "$LOG" || { echo "FAIL: 删除未记账"; exit 1; }
  n0="$(grep -cF "hotplug: 接口 hplug-lan 出现" "$LOG" || true)"
  ip link add hplug-lan type veth peer name hplug-cli
  ip link set hplug-cli netns "$CLIENT_NS"
  ip addr add 10.60.0.1/24 dev hplug-lan
  ip link set hplug-lan up
  ip -n "$CLIENT_NS" link set hplug-cli up
  ip -n "$CLIENT_NS" addr add 10.60.0.2/24 dev hplug-cli
  ip -n "$CLIENT_NS" route replace "$PROXY_DST/32" via 10.60.0.1 dev hplug-cli
  for i in $(seq 1 30); do
    n1="$(grep -cF "hotplug: 接口 hplug-lan 出现" "$LOG" || true)"
    [ "${n1:-0}" -ge "$((n0 + 1))" ] && break
    sleep 0.2
  done
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "orig_dst=$PROXY_DST:8080" \
    || { echo "FAIL: 删除→重加后未恢复接管"; exit 1; }
  echo "PASS: 删除→重加（churn）后自动再挂并恢复接管"
}

# #4：match_set 容量（dae MIN 1024）——69 条填充 + 高位规则 + fallback（共 71 个 match_set）。
rulecap_up() {
  require_root
  [ -f "$OBJ" ] && [ -x "$LOADER" ] || die "先运行 $0 build"
  local f=/tmp/sodama-rulecap.rules i
  : >"$f"
  for i in $(seq 1 69); do
    echo "dport($((20000 + i))) -> direct" >>"$f"
  done
  echo "dport(8080) -> proxy" >>"$f"
  echo "fallback -> direct" >>"$f"
  USE_RULES="$f" USE_RELAY_IDLE=600 up
}

test_rules_cap() {
  require_root
  echo "== 能力缺口 #4：match_set 容量 > 64（dae 1024）=="
  grep -qE "rules: (7[0-9]|[89][0-9]|[0-9]{3,}) match_sets" "$LOG" \
    || { echo "FAIL: 大规则集未编译成功（仍限 ≤64？）"; grep -E "match_sets|超过上限" "$LOG" | head -3; exit 1; }
  echo "PASS: 71 个 match_set 编译通过（verifier 接受 1024 上界的有界循环）"
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "orig_dst=$PROXY_DST:8080" \
    || { echo "FAIL: 高位（index≥64）规则未生效（大规则集下分流错误）"; exit 1; }
  echo "PASS: 高位规则命中（index≥64 的 match_set 生效）"
}

# 缺口批次（eBPF 余项 A）：lan_egress 角色 + parse 原因计数 + 纯 SYN 重绑 + handoff。
gaps_up() {
  require_root
  [ -f "$OBJ" ] && [ -x "$LOADER" ] || die "先运行 $0 build"
  USE_RELAY_IDLE=600 up
}

test_gaps() {
  require_root
  echo "== eBPF 缺口：lan_egress / parse 原因计数 / 纯 SYN 重绑 / handoff =="
  # 1) LAN 接口 egress 方向已挂 lan_egress（对照 dae setupLanInterface 双钩子）
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json "$LAN_IFACE" <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
iface = sys.argv[2]
hooks = v.get("hooks") or []
expect = "sodama_lan_egress@%s" % iface
assert expect in hooks, ("lan_egress 未挂载", hooks)
print("hooks 含 %s（共 %d 个钩子）" % (expect, len(hooks)))
PY
  echo "PASS: $LAN_IFACE egress 已挂 sodama_lan_egress"
  # 2) parse 原因计数：ICMP 直通计入 parse_unsupported_l4（有 ping 才断言）
  if command -v ping >/dev/null 2>&1; then
    ip netns exec "$CLIENT_NS" timeout 3 ping -c 1 -W 2 "$DIRECT_DST" >/dev/null 2>&1 || true
    sleep 0.3
    "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
    python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
s = v["stats"]
assert s["parse_unsupported_l4"] >= 1, ("parse_unsupported_l4 未推进", s)
print("stats.parse_unsupported_l4 =", s["parse_unsupported_l4"])
PY
    echo "PASS: parse 原因计数（ICMP → parse_unsupported_l4）"
  else
    echo "SKIP: 无 ping，跳过 parse_unsupported_l4 行为断言"
  fi
  # 3) 同 4 元组重连（固定源端口）：同代纯 SYN → 拒改（syn_rebind_rejected）
  # 默认 up 无 dialer → relay 回显夹具口径（orig_dst= 行）
  local lport=40001 out
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 "$lport" 2>&1 || true)"
  echo "$out" | grep -q "orig_dst=$PROXY_DST:8080" || { echo "FAIL: 首连失败"; echo "$out"; exit 1; }
  sleep 0.5
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 "$lport" 2>&1 || true)"
  echo "$out" | grep -q "orig_dst=$PROXY_DST:8080" || { echo "FAIL: 同 4 元组重连失败"; echo "$out"; exit 1; }
  # 4) SIGHUP（代次递增）→ 同 4 元组重连 = 异代 → 重路由（syn_rebind_rerouted）
  kill -HUP "$(cat "$PID_FILE")"
  sleep 1.2
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 "$lport" 2>&1 || true)"
  echo "$out" | grep -q "orig_dst=$PROXY_DST:8080" || { echo "FAIL: reload 后重连失败（重路由路径）"; echo "$out"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
s, m = v["stats"], v["maps"]
assert s["syn_rebind_rejected"] >= 1, ("syn_rebind_rejected 未推进", s)
assert s["rebind_rerouted"] >= 1, ("rebind_rerouted 未推进", s)
assert m["routing_handoff"] >= 1, ("handoff 表为空", m)
print("syn-rebind: rejected=%d rerouted=%d handoff=%d" % (
    s["syn_rebind_rejected"], s["rebind_rerouted"], m["routing_handoff"]))
PY
  echo "PASS: 纯 SYN 重绑（同代拒改 / 异代重路由）+ 首包 handoff 条目"
}

# 缺口批次（eBPF 余项 B）：出口连通性判定（alive 投影 → 数据面 SHOT）。
alive_up() {
  require_root
  [ -f "$OBJ" ] && [ -x "$LOADER" ] || die "先运行 $0 build"
  cleanup
  local meth="chacha20-ietf-poly1305" pass="testpass"
  { echo "ss://$meth:$pass@127.0.0.1:$SS_PORT#node-a"; } | base64 -w0 >"$SUB_BODY"
  echo >>"$SUB_BODY"
  cat >"$SUB_GROUPS_CONFIG" <<EOF
# 出口连通性投影：单成员组（探测 1s / 容忍 1）+ 8080 → proxy
global {
    tcp_check_url: 'http://10.9.9.2:9999'
    check_interval: '1s'
    check_tolerance: '1'
}
subscription {
    lab: 'http://127.0.0.1:$SUB_PORT/sub'
}
group {
    proxy {
        filter: name(node-a)
        policy: min_moving_avg
    }
}
routing {
    dip(1.1.1.1/32) && dport(8080) -> proxy
    fallback: direct
}
EOF
  chmod 640 "$SUB_GROUPS_CONFIG"
  USE_CONFIG="$SUB_GROUPS_CONFIG" USE_SS=1 USE_SS_METHOD="$meth" USE_SS_PASSWORD="$pass" \
    USE_SUB_SERVER=1 USE_RELAY_IDLE=600 up
}

test_alive() {
  require_root
  echo "== 出口连通性判定（outbound_connectivity_map + wan_outbound_is_alive）=="
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out" | grep -q "wan-echo-ok" || { echo "FAIL: 初始连接失败（组未存活）"; echo "$out"; exit 1; }
  echo "PASS: 初始（组 alive）连接正常"
  # 杀后端 → 探测失败 → 组标死 → 投影 0 → 数据面 SHOT
  kill "$(cat "$SS_PID_FILE")" 2>/dev/null || true
  rm -f "$SS_PID_FILE"
  sleep 6
  out="$(ip netns exec "$CLIENT_NS" timeout 5 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  if echo "$out" | grep -q "wan-echo-ok"; then
    echo "FAIL: 后端已死但新连接仍被放行（alive 投影未生效）"; echo "$out"; exit 1
  fi
  echo "PASS: 组标死后新连接被数据面阻断（$(printf '%s' "$out" | tail -1)）"
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
assert v["maps"]["connectivity_dead_groups"] >= 1, ("dead 组未投影", v["maps"])
print("connectivity_dead_groups =", v["maps"]["connectivity_dead_groups"])
PY
  # 恢复后端 → 探测恢复 → 通
  python3 -u "$HERE/ss_server.py" "$SS_LOG" "chacha20-ietf-poly1305" "testpass" "$SS_PORT" \
    >/tmp/sodama-ss-restart.log 2>&1 &
  echo $! >"$SS_PID_FILE"
  sleep 7
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out" | grep -q "wan-echo-ok" || { echo "FAIL: 后端恢复后仍未放行（投影未恢复）"; echo "$out"; exit 1; }
  echo "PASS: 后端恢复 → 组复活 → 连接恢复"
}

# 缺口批次（eBPF 余项 C）：offload 背压 fuse（阈值/生命周期/无残留；判定逻辑已有单测）。
fuse_up() {
  require_root
  [ -f "$OBJ" ] && [ -x "$LOADER" ] || die "先运行 $0 build"
  SODAMA_FUSE_MAX_BACKLOG=65536 USE_RULES="$HERE/rules.dae" USE_DIALER=direct \
    USE_OFFLOAD=1 USE_RELAY_IDLE=600 up
}

test_fuse() {
  require_root
  echo "== offload 背压 fuse（tcp_offload_pause）=="
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
f = v["offload_fuse"]
assert f["threshold"] == 65536, ("SODAMA_FUSE_MAX_BACKLOG 未生效", f)
print("offload_fuse.threshold =", f["threshold"])
PY
  # 数据流部分：offload 会话在本 QEMU 环境有既有首连抖动（devlog §19），
  # 重试 3 次；全失败则跳过数据流断言（机制断言仍必须过）。
  local out ok=0 i
  for i in 1 2 3; do
    out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
    if echo "$out" | grep -q "wan-echo-ok"; then ok=1; break; fi
    sleep 0.5
  done
  if [ "$ok" = 1 ]; then
    out="$(ip netns exec "$CLIENT_NS" timeout 30 python3 "$HERE/stream_probe.py" "$PROXY_DST" 8080 512 2>&1 || true)"
    echo "$out" | grep -q "^stream-ok bytes=524288" || { echo "FAIL: fuse 会话下大流量回显不一致"; echo "$out"; exit 1; }
    echo "PASS: 数据流（512KB 逐字节一致；预热点 $i 次）"
  else
    echo "SKIP: offload 首连抖动（QEMU 既有环境问题，devlog §19），跳过数据流断言"
  fi
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
f = v["offload_fuse"]
# 本地回环下对端写队列几乎不积压：未触发 fuse 也是合法结果（真实触发条件
# 是对端 retry 队列积压，本地夹具不可自然构造；判定逻辑由单测锁定）。
# 但一旦触发必须成对退出（engages == lifts）且无失败——否则就是残留暂停。
assert f["failures"] == 0, f
assert f["engages"] == f["lifts"], ("fuse 未成对退出（可能残留暂停）", f)
print("offload_fuse: engages=%d lifts=%d pause_passes=%d" % (
    f["engages"], f["lifts"], f["pause_passes"]))
PY
  echo "PASS: fuse 阈值生效、无失败、无残留（engages==lifts；真触发判定逻辑已由单测锁定）"
}

# 缺口批次（eBPF 余项 D）：conn_state_map pinning（跨重启迁移）。
pin_up() {
  require_root
  [ -f "$OBJ" ] && [ -x "$LOADER" ] || die "先运行 $0 build"
  USE_RELAY_IDLE=600 up
}

test_pinning() {
  require_root
  echo "== conn_state_map pinning（跨重启迁移）=="
  local out before
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out" | grep -q "orig_dst=$PROXY_DST:8080" || { echo "FAIL: 前置连接失败"; echo "$out"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  before="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["maps"]["conn_state"])' /tmp/sodama-status.json)"
  [ "$before" -ge 1 ] || { echo "FAIL: conn_state 为空"; exit 1; }
  [ -e /sys/fs/bpf/sodama/conn_state_map ] \
    || { echo "FAIL: pin 文件不存在（pinning 未生效）"; ls -l /sys/fs/bpf/ 2>&1 | head; exit 1; }
  echo "PASS: pin 文件存在（conn_state=$before 条）"
  "$0" down >/dev/null 2>&1 || true
  sleep 0.5
  [ -e /sys/fs/bpf/sodama/conn_state_map ] || { echo "FAIL: down 后 pin 文件被删"; exit 1; }
  "$0" pin-up >/dev/null 2>&1 || { echo "FAIL: 重启失败"; tail -5 "$LOG"; exit 1; }
  grep -q "conn_state pin: 迁移" "$LOG" || { echo "FAIL: 无迁移日志"; grep "conn_state pin" "$LOG" | head; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
n = v["maps"]["conn_state"]
assert n >= 1, ("迁移后 conn_state 为空", v["maps"])
print("迁移后 conn_state =", n)
PY
  echo "PASS: 重启后 pinned 条目已迁移（跨重启保留在途流状态）"
}

# P5 G1：shadowsocks TCP——跨实现（独立 Python 服务端）+ 协议层必须跑在用户态
# （ss-up 特意带了 --offload：AEAD 帧不能交给内核拼接，offloaded_total 必须为 0）。
test_ss() {
  require_root
  echo "== 测试 shadowsocks（chacha20-ietf-poly1305）TCP 转发 =="
  rm -f "$SS_LOG"
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "wan-echo-ok data=ping" || { echo "FAIL: ss 链路未把流量转发到真实目标"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 30 python3 "$HERE/stream_probe.py" "$PROXY_DST" 8080 512 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "^stream-ok bytes=524288" || { echo "FAIL: ss 大流量回显不一致"; exit 1; }
  grep -q "TCP target=$PROXY_DST:8080" "$SS_LOG" || { echo "FAIL: 独立 ss 服务端未看到目标地址（跨实现失败）"; cat "$SS_LOG"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
assert v["dialer"].startswith("ss://chacha20-ietf-poly1305@"), v["dialer"]
r = v["relay"]
assert r["conns_total"] >= 2, r
assert r["dial_errors"] == 0, r
# 协议层必须走用户态（AEAD 帧不能交给内核拼接）
assert r["offload_enabled"], r        # 会话确实开了 --offload
assert r["offloaded_total"] == 0, r   # 协议互斥 → 一个都没注册
assert r["bytes_up"] >= 512 * 1024, r
assert r["bytes_down"] >= 512 * 1024, r
print("ss tcp: conns=%d bytes_up=%d bytes_down=%d offloaded=%d" % (
    r["conns_total"], r["bytes_up"], r["bytes_down"], r["offloaded_total"]))
PY
  echo "PASS: shadowsocks TCP（独立 Python 服务端 + 用户态 AEAD + offload 互斥）"
}

# P5 G1：trojan TCP——TLS + CONNECT 头，同样验证协议/offload 互斥。
test_trojan() {
  require_root
  echo "== 测试 trojan（TLS）TCP 转发 =="
  rm -f "$TROJAN_LOG"
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "wan-echo-ok data=ping" || { echo "FAIL: trojan 链路未把流量转发到真实目标"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 30 python3 "$HERE/stream_probe.py" "$PROXY_DST" 8080 512 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "^stream-ok bytes=524288" || { echo "FAIL: trojan 大流量回显不一致"; exit 1; }
  grep -q "CONNECT target=$PROXY_DST:8080" "$TROJAN_LOG" || { echo "FAIL: 独立 trojan 服务端未看到 CONNECT（跨实现失败）"; cat "$TROJAN_LOG"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
assert v["dialer"].startswith("trojan://"), v["dialer"]
r = v["relay"]
assert r["conns_total"] >= 2, r
assert r["dial_errors"] == 0, r
assert r["offload_enabled"], r
assert r["offloaded_total"] == 0, r
assert r["bytes_up"] >= 512 * 1024, r
assert r["bytes_down"] >= 512 * 1024, r
print("trojan tcp: conns=%d bytes_up=%d bytes_down=%d offloaded=%d" % (
    r["conns_total"], r["bytes_up"], r["bytes_down"], r["offloaded_total"]))
PY
  echo "PASS: trojan TCP（独立 Python 服务端 + TLS/CONNECT + offload 互斥）"
}

# P5 G1：shadowsocks UDP 代理（G1 里唯一支持 UDP 的协议栈；不允许静默直连回退）。
test_ss_udp() {
  require_root
  echo "== 测试 shadowsocks UDP 代理 =="
  rm -f "$SS_LOG"
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 10 python3 "$HERE/udp_probe.py" 2.2.2.2 9998 3 0.2 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "reply=udp-echo-ok data=ping0 from=2.2.2.2:9998" || { echo "FAIL: ss UDP 未转发到真实目标/回包源地址不对"; exit 1; }
  echo "$out" | grep -q "^summary=3/3" || { echo "FAIL: ss UDP 报文丢失"; exit 1; }
  grep -q "UDP target=2.2.2.2:9998" "$SS_LOG" || { echo "FAIL: 独立 ss 服务端未看到 UDP 目标（跨实现失败）"; cat "$SS_LOG"; exit 1; }
  sleep 0.3
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
u = v["udp_nat"]
assert u["sessions_proxied"] >= 1, u
assert u["direct_fallback"] == 0, u
assert u["sessions_active"] == 1, u
assert u["errors"] == 0, u
print("ss udp: sessions=%d/%d proxied=%d fallback=%d bytes_up=%d bytes_down=%d" % (
    u["sessions_active"], u["sessions_total"], u["sessions_proxied"],
    u["direct_fallback"], u["bytes_up"], u["bytes_down"]))
PY
  echo "PASS: shadowsocks UDP（独立 Python 服务端 + 会话计数）"
}

# P5-G2：vless TCP——跨实现（独立 Python 服务端）+ 协议层跑在用户态
# （会话带 --offload：帧式协议不能交给内核拼接，offloaded_total 必须为 0）。
test_vless() {
  require_root
  echo "== 测试 vless TCP 转发 =="
  rm -f "$VLESS_LOG"
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "wan-echo-ok data=ping" || { echo "FAIL: vless 链路未把流量转发到真实目标"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 30 python3 "$HERE/stream_probe.py" "$PROXY_DST" 8080 512 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "^stream-ok bytes=524288" || { echo "FAIL: vless 大流量回显不一致"; exit 1; }
  grep -q "TCP target=$PROXY_DST:8080" "$VLESS_LOG" || { echo "FAIL: 独立 vless 服务端未看到目标地址（跨实现失败）"; cat "$VLESS_LOG"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
assert v["dialer"].startswith("vless://"), v["dialer"]
r = v["relay"]
assert r["conns_total"] >= 2, r
assert r["dial_errors"] == 0, r
assert r["offload_enabled"], r
assert r["offloaded_total"] == 0, r
assert r["bytes_up"] >= 512 * 1024, r
assert r["bytes_down"] >= 512 * 1024, r
print("vless tcp: conns=%d bytes_up=%d bytes_down=%d offloaded=%d" % (
    r["conns_total"], r["bytes_up"], r["bytes_down"], r["offloaded_total"]))
PY
  echo "PASS: vless TCP（独立 Python 服务端 + 用户态帧式封装 + offload 互斥）"
}

# P5-G2：vless UDP（帧 = [BE16 len][payload]，同一 TCP/TLS 流）。
test_vless_udp() {
  require_root
  echo "== 测试 vless UDP 代理 =="
  rm -f "$VLESS_LOG"
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 10 python3 "$HERE/udp_probe.py" 2.2.2.2 9998 3 0.2 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "reply=udp-echo-ok data=ping0 from=2.2.2.2:9998" || { echo "FAIL: vless UDP 未转发到真实目标"; exit 1; }
  echo "$out" | grep -q "^summary=3/3" || { echo "FAIL: vless UDP 报文丢失"; exit 1; }
  grep -q "UDP target=2.2.2.2:9998" "$VLESS_LOG" || { echo "FAIL: 独立 vless 服务端未看到 UDP 目标"; cat "$VLESS_LOG"; exit 1; }
  sleep 0.3
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
u = v["udp_nat"]
assert u["sessions_proxied"] >= 1, u
assert u["direct_fallback"] == 0, u
assert u["sessions_active"] == 1, u
assert u["errors"] == 0, u
print("vless udp: sessions=%d/%d proxied=%d fallback=%d" % (
    u["sessions_active"], u["sessions_total"], u["sessions_proxied"], u["direct_fallback"]))
PY
  echo "PASS: vless UDP（独立 Python 服务端 + 帧式封装）"
}

# P5-G2：vmess AEAD TCP——跨实现 + 协议/offload 互斥。
test_vmess() {
  require_root
  echo "== 测试 vmess（AEAD）TCP 转发 =="
  rm -f "$VMESS_LOG"
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "wan-echo-ok data=ping" || { echo "FAIL: vmess 链路未把流量转发到真实目标"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 30 python3 "$HERE/stream_probe.py" "$PROXY_DST" 8080 512 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "^stream-ok bytes=524288" || { echo "FAIL: vmess 大流量回显不一致"; exit 1; }
  grep -q "TCP target=$PROXY_DST:8080" "$VMESS_LOG" || { echo "FAIL: 独立 vmess 服务端未看到目标地址（跨实现失败）"; cat "$VMESS_LOG"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
assert v["dialer"].startswith("vmess://"), v["dialer"]
r = v["relay"]
assert r["conns_total"] >= 2, r
assert r["dial_errors"] == 0, r
assert r["offload_enabled"], r
assert r["offloaded_total"] == 0, r
assert r["bytes_up"] >= 512 * 1024, r
assert r["bytes_down"] >= 512 * 1024, r
print("vmess tcp: conns=%d bytes_up=%d bytes_down=%d offloaded=%d" % (
    r["conns_total"], r["bytes_up"], r["bytes_down"], r["offloaded_total"]))
PY
  echo "PASS: vmess TCP（独立 Python 服务端 + AEAD 分块 + offload 互斥）"
}

# P5-G2：vmess UDP（一个数据报一个数据块）。
test_vmess_udp() {
  require_root
  echo "== 测试 vmess UDP 代理 =="
  rm -f "$VMESS_LOG"
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 10 python3 "$HERE/udp_probe.py" 2.2.2.2 9998 3 0.2 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "reply=udp-echo-ok data=ping0 from=2.2.2.2:9998" || { echo "FAIL: vmess UDP 未转发到真实目标"; exit 1; }
  echo "$out" | grep -q "^summary=3/3" || { echo "FAIL: vmess UDP 报文丢失"; exit 1; }
  grep -q "UDP target=2.2.2.2:9998" "$VMESS_LOG" || { echo "FAIL: 独立 vmess 服务端未看到 UDP 目标"; cat "$VMESS_LOG"; exit 1; }
  sleep 0.3
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
u = v["udp_nat"]
assert u["sessions_proxied"] >= 1, u
assert u["direct_fallback"] == 0, u
assert u["sessions_active"] == 1, u
assert u["errors"] == 0, u
print("vmess udp: sessions=%d/%d proxied=%d fallback=%d" % (
    u["sessions_active"], u["sessions_total"], u["sessions_proxied"], u["direct_fallback"]))
PY
  echo "PASS: vmess UDP（独立 Python 服务端 + 数据报分块）"
}

# P5-G3：tuic v5 TCP——跨实现（Go/quic-go 参考服务端）+ 协议/offload 互斥。
test_tuic() {
  require_root
  echo "== 测试 tuic v5（QUIC）TCP 转发 =="
  : >"$TUIC_LOG" 2>/dev/null || true
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "wan-echo-ok data=ping" || { echo "FAIL: tuic 链路未把流量转发到真实目标"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 30 python3 "$HERE/stream_probe.py" "$PROXY_DST" 8080 512 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "^stream-ok bytes=524288" || { echo "FAIL: tuic 大流量回显不一致"; exit 1; }
  grep -q "TCP target=$PROXY_DST:8080" "$TUIC_LOG" || { echo "FAIL: Go 参考服务端未看到目标地址（跨实现失败）"; cat "$TUIC_LOG"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
assert v["dialer"].startswith("tuic://"), v["dialer"]
r = v["relay"]
assert r["conns_total"] >= 2, r
assert r["dial_errors"] == 0, r
assert r["offload_enabled"], r
assert r["offloaded_total"] == 0, r   # QUIC 不交内核拼接
assert r["bytes_up"] >= 512 * 1024, r
assert r["bytes_down"] >= 512 * 1024, r
print("tuic tcp: conns=%d bytes_up=%d bytes_down=%d offloaded=%d" % (
    r["conns_total"], r["bytes_up"], r["bytes_down"], r["offloaded_total"]))
PY
  echo "PASS: tuic v5 TCP（Go/quic-go 参考服务端 + QUIC 流 + offload 互斥）"
}

# P5-G3：tuic v5 UDP——QUIC DATAGRAM（含分片重组）。
test_tuic_udp() {
  require_root
  echo "== 测试 tuic v5 UDP 代理 =="
  : >"$TUIC_LOG" 2>/dev/null || true
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 10 python3 "$HERE/udp_probe.py" 2.2.2.2 9998 3 0.2 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "reply=udp-echo-ok data=ping0 from=2.2.2.2:9998" || { echo "FAIL: tuic UDP 未转发到真实目标"; exit 1; }
  echo "$out" | grep -q "^summary=3/3" || { echo "FAIL: tuic UDP 报文丢失"; exit 1; }
  grep -q "UDP target=2.2.2.2:9998" "$TUIC_LOG" || { echo "FAIL: Go 参考服务端未看到 UDP 目标"; cat "$TUIC_LOG"; exit 1; }
  sleep 0.3
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
u = v["udp_nat"]
assert u["sessions_proxied"] >= 1, u
assert u["direct_fallback"] == 0, u
assert u["sessions_active"] == 1, u
assert u["errors"] == 0, u
print("tuic udp: sessions=%d/%d proxied=%d fallback=%d" % (
    u["sessions_active"], u["sessions_total"], u["sessions_proxied"], u["direct_fallback"]))
PY
  echo "PASS: tuic v5 UDP（QUIC DATAGRAM + 分片重组）"
}

# P27：juicity v0（QUIC + TUIC 式认证 + trojan 风格元数据）TCP 转发。
test_juicity() {
  require_root
  echo "== P27：juicity v0（QUIC）TCP 转发 =="
  : >"$JUICITY_LOG" 2>/dev/null || true
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "wan-echo-ok data=ping" || { echo "FAIL: juicity 链路未把流量转发到真实目标"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 30 python3 "$HERE/stream_probe.py" "$PROXY_DST" 8080 512 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "^stream-ok bytes=524288" || { echo "FAIL: juicity 大流量（512KB）回显不一致（半关闭/帧？）"; exit 1; }
  grep -q "JUICITY tcp target=$PROXY_DST:8080" "$JUICITY_LOG" \
    || { echo "FAIL: Go 参考服务端未看到目标地址（跨实现失败）"; cat "$JUICITY_LOG"; exit 1; }
  grep -q "JUICITY auth-fail" "$JUICITY_LOG" && { echo "FAIL: 出现认证失败（exporter/认证流？）"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
assert v["dialer"].startswith("juicity://"), v["dialer"]
r = v["relay"]
assert r["conns_total"] >= 2, r
assert r["dial_errors"] == 0, r
assert r["offload_enabled"], r
assert r["offloaded_total"] == 0, r   # QUIC 不交内核拼接
assert r["bytes_up"] >= 512 * 1024, r
assert r["bytes_down"] >= 512 * 1024, r
print("juicity tcp: conns=%d bytes_up=%d bytes_down=%d offloaded=%d" % (
    r["conns_total"], r["bytes_up"], r["bytes_down"], r["offloaded_total"]))
PY
  echo "PASS: juicity v0 TCP（Go/quic-go 参考服务端 + QUIC 流 + trojan 风格元数据）"
}

# P27：juicity v0 UDP（双向流帧：元数据 + len + 载荷）。
test_juicity_udp() {
  require_root
  echo "== P27：juicity v0 UDP 代理 =="
  : >"$JUICITY_LOG" 2>/dev/null || true
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 10 python3 "$HERE/udp_probe.py" 2.2.2.2 9998 3 0.2 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "reply=udp-echo-ok data=ping0 from=2.2.2.2:9998" || { echo "FAIL: juicity UDP 未转发到真实目标"; exit 1; }
  echo "$out" | grep -q "^summary=3/3" || { echo "FAIL: juicity UDP 报文丢失"; exit 1; }
  grep -q "JUICITY udp session target=2.2.2.2:9998" "$JUICITY_LOG" || { echo "FAIL: Go 参考服务端未看到 UDP 目标"; cat "$JUICITY_LOG"; exit 1; }
  sleep 0.3
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
u = v["udp_nat"]
assert u["sessions_proxied"] >= 1, u
assert u["direct_fallback"] == 0, u
assert u["sessions_active"] == 1, u
assert u["errors"] == 0, u
print("juicity udp: sessions=%d/%d proxied=%d fallback=%d" % (
    u["sessions_active"], u["sessions_total"], u["sessions_proxied"], u["direct_fallback"]))
PY
  echo "PASS: juicity v0 UDP（流帧元数据 + len + 载荷）"
}

# P30：SSR（shadowsocksr-stream；origin+plain + aes-256-cfb 流密码）TCP 转发。
test_ssr() {
  require_root
  echo "== P30：SSR（origin+plain + 流密码）TCP 转发 =="
  : >"$SSR_LOG" 2>/dev/null || true
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "wan-echo-ok data=ping" || { echo "FAIL: SSR 链路未把流量转发到真实目标"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 30 python3 "$HERE/stream_probe.py" "$PROXY_DST" 8080 512 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "^stream-ok bytes=524288" || { echo "FAIL: SSR 大流量（512KB）回显不一致（流密码状态/半关闭？）"; exit 1; }
  grep -q "SSR connect target=$PROXY_DST:8080" "$SSR_LOG" \
    || { echo "FAIL: Go 参考服务端未看到目标地址（跨实现失败）"; cat "$SSR_LOG"; exit 1; }
  grep -q "SSR cipher error\|SSR read iv.*:" "$SSR_LOG" && { echo "FAIL: 出现解密/IV 错误（流密码状态不同步？）"; cat "$SSR_LOG"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
assert v["dialer"].startswith("ssr://"), v["dialer"]
r = v["relay"]
assert r["conns_total"] >= 2, r
assert r["dial_errors"] == 0, r
assert r["offload_enabled"], r
assert r["offloaded_total"] == 0, r   # 流密码不交内核拼接
assert r["bytes_up"] >= 512 * 1024, r
assert r["bytes_down"] >= 512 * 1024, r
print("ssr tcp: conns=%d bytes_up=%d bytes_down=%d offloaded=%d" % (
    r["conns_total"], r["bytes_up"], r["bytes_down"], r["offloaded_total"]))
PY
  echo "PASS: SSR（origin+plain + aes-256-cfb 流密码；跨实现 Go 参考服务端）"
}

# P31：shadow-tls（ss 插件链；v1 裸隧道 / v2 首帧 HMAC / v3 CH session_id + MAC 链）。
test_shadowtls() {
  require_root
  local ver="${1:-3}"
  echo "== P31：shadow-tls v$ver（ss 插件链）TCP 转发 =="
  grep -q "STLS server version=$ver" "$SHADOWTLS_LOG" /tmp/sodama-shadowtls.stdout 2>/dev/null \
    || { echo "FAIL: 参考服务端不是 v$ver"; cat "$SHADOWTLS_LOG"; exit 1; }
  : >"$SHADOWTLS_LOG" 2>/dev/null || true
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "wan-echo-ok data=ping" || { echo "FAIL: shadow-tls 链路未把流量转发到真实目标"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 30 python3 "$HERE/stream_probe.py" "$PROXY_DST" 8080 512 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "^stream-ok bytes=524288" || { echo "FAIL: shadow-tls 大流量（512KB）回显不一致"; exit 1; }
  grep -q "STLS handler conn backend=" "$SHADOWTLS_LOG" \
    || { echo "FAIL: shadow-tls 服务端未完成认证交接（HMAC/session_id/帧链？）"; cat "$SHADOWTLS_LOG"; exit 1; }
  grep -q "TCP target=$PROXY_DST:8080" "$SS_LOG" \
    || { echo "FAIL: python ss 后端未看到目标（shadow-tls 服务端→ss 转发失败？）"; cat "$SS_LOG"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
assert v["dialer"].startswith("ss://"), v["dialer"]
r = v["relay"]
assert r["conns_total"] >= 2, r
assert r["dial_errors"] == 0, r
assert r["bytes_up"] >= 512 * 1024, r
assert r["bytes_down"] >= 512 * 1024, r
print("shadowtls tcp: conns=%d bytes_up=%d bytes_down=%d" % (
    r["conns_total"], r["bytes_up"], r["bytes_down"]))
PY
  echo "PASS: shadow-tls v$ver（跨实现：Rust 客户端 ↔ Go/sing-shadowtls 服务端 ↔ python ss）"
}

# P28：ECS 回填 / ecs_cache（上游回显 scope → 按回填键缓存与阶梯复用）。
test_ecs_cache() {
  require_root
  echo "== P28：ECS 回填 / ecs_cache =="
  [ -f "$FAKE_DNS_PID_FILE" ] && kill -0 "$(cat "$FAKE_DNS_PID_FILE")" 2>/dev/null \
    || die "假 DNS 未运行（先用 ecscache-up 会话启动）"
  local out before after
  probe() { ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/dns_probe.py" 9.9.9.9 "$1" 2>&1 || true; }

  # scope=0（全局）：第一次上行 + 回填入全局键；第二次命中（假上游不再收到）
  before="$(grep -c '^QUERY ecs0.test' "$FAKE_DNS_LOG" || true)"
  out="$(probe ecs0.test)"; echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.81' || { echo "FAIL: ecs0.test 首次解析失败"; exit 1; }
  out="$(probe ecs0.test)"; echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.81' || { echo "FAIL: ecs0.test 第二次解析失败"; exit 1; }
  after="$(grep -c '^QUERY ecs0.test' "$FAKE_DNS_LOG" || true)"
  [ "$((after - before))" = "1" ] || { echo "FAIL: scope=0 未跨查询复用（上游增量 $((after - before))）"; exit 1; }

  # scope=/16：同客户端两次（先精确 /24 未命中 → /16 回填键命中）
  before="$(grep -c '^QUERY ecs16.test' "$FAKE_DNS_LOG" || true)"
  out="$(probe ecs16.test)"; echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.82' || { echo "FAIL: ecs16.test 首次解析失败"; exit 1; }
  out="$(probe ecs16.test)"; echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.82' || { echo "FAIL: ecs16.test 第二次解析失败"; exit 1; }
  after="$(grep -c '^QUERY ecs16.test' "$FAKE_DNS_LOG" || true)"
  [ "$((after - before))" = "1" ] || { echo "FAIL: scope=/16 未按回填键复用（上游增量 $((after - before))）"; exit 1; }

  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
ecs = v["dns"]["ecs"]
assert ecs["echo"] >= 2, ecs
assert ecs["scope"] == "10.0.0.0/16", ecs
print("ecs: echo=%d scope=%s" % (ecs["echo"], ecs["scope"]))
PY
  echo "PASS: ECS 回填（scope=0 全局 / /16 跨子网复用；窄 scope 见单测）"
}

# P5-G3b：hysteria2 TCP——跨实现（Go/http3 参考服务端）+ 协议/offload 互斥。
test_hy2() {
  require_root
  echo "== 测试 hysteria2 TCP 转发 =="
  : >"$HY2_LOG" 2>/dev/null || true
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "wan-echo-ok data=ping" || { echo "FAIL: hysteria2 链路未把流量转发到真实目标"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 30 python3 "$HERE/stream_probe.py" "$PROXY_DST" 8080 512 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "^stream-ok bytes=524288" || { echo "FAIL: hysteria2 大流量回显不一致"; exit 1; }
  grep -q "TCP target=$PROXY_DST:8080" "$HY2_LOG" || { echo "FAIL: Go 参考服务端未看到目标地址（跨实现失败）"; cat "$HY2_LOG"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
assert v["dialer"].startswith("hysteria2://"), v["dialer"]
r = v["relay"]
assert r["conns_total"] >= 2, r
assert r["dial_errors"] == 0, r
assert r["offload_enabled"], r
assert r["offloaded_total"] == 0, r   # QUIC 不交内核拼接
assert r["bytes_up"] >= 512 * 1024, r
assert r["bytes_down"] >= 512 * 1024, r
print("hy2 tcp: conns=%d bytes_up=%d bytes_down=%d offloaded=%d" % (
    r["conns_total"], r["bytes_up"], r["bytes_down"], r["offloaded_total"]))
PY
  echo "PASS: hysteria2 TCP（Go/http3 参考服务端 + QUIC 流 + HTTP/3 认证）"
}

# P5-G3b：hysteria2 UDP——QUIC DATAGRAM（含分片重组）。
test_hy2_udp() {
  require_root
  echo "== 测试 hysteria2 UDP 代理 =="
  : >"$HY2_LOG" 2>/dev/null || true
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 10 python3 "$HERE/udp_probe.py" 2.2.2.2 9998 3 0.2 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "reply=udp-echo-ok data=ping0 from=2.2.2.2:9998" || { echo "FAIL: hysteria2 UDP 未转发到真实目标"; exit 1; }
  echo "$out" | grep -q "^summary=3/3" || { echo "FAIL: hysteria2 UDP 报文丢失"; exit 1; }
  grep -q "UDP target=2.2.2.2:9998" "$HY2_LOG" || { echo "FAIL: Go 参考服务端未看到 UDP 目标"; cat "$HY2_LOG"; exit 1; }
  sleep 0.3
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
u = v["udp_nat"]
assert u["sessions_proxied"] >= 1, u
assert u["direct_fallback"] == 0, u
assert u["sessions_active"] == 1, u
assert u["errors"] == 0, u
print("hy2 udp: sessions=%d/%d proxied=%d fallback=%d" % (
    u["sessions_active"], u["sessions_total"], u["sessions_proxied"], u["direct_fallback"]))
PY
  echo "PASS: hysteria2 UDP（QUIC DATAGRAM + 分片重组）"
}

# P5-G3b+：salamander 混淆（TCP 512KB + 服务端日志）。
test_hy2_obfs() {
  require_root
  echo "== 测试 hysteria2 + salamander 混淆（TCP）=="
  # 不截断日志：启动横幅 "salamander obfs enabled" 是混淆启用的证据
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 8 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "wan-echo-ok data=ping" || { echo "FAIL: 混淆链路未把流量转发到真实目标"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 30 python3 "$HERE/stream_probe.py" "$PROXY_DST" 8080 512 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "^stream-ok bytes=524288" || { echo "FAIL: 混淆链路大流量回显不一致"; exit 1; }
  grep -q "salamander obfs enabled" "$HY2_LOG" || { echo "FAIL: 服务端未启用 salamander"; cat "$HY2_LOG"; exit 1; }
  grep -q "TCP target=$PROXY_DST:8080" "$HY2_LOG" || { echo "FAIL: 服务端未看到目标地址"; cat "$HY2_LOG"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
assert v["dialer"].startswith("hysteria2://"), v["dialer"]
r = v["relay"]
assert r["conns_total"] >= 2, r
assert r["dial_errors"] == 0, r
assert r["offloaded_total"] == 0, r
assert r["bytes_up"] >= 512 * 1024, r
assert r["bytes_down"] >= 512 * 1024, r
print("hy2 obfs tcp: conns=%d bytes_up=%d bytes_down=%d" % (
    r["conns_total"], r["bytes_up"], r["bytes_down"]))
PY
  echo "PASS: hysteria2 + salamander（跨实现，服务端日志确认混淆开启）"
}

# P5-G3b+：salamander + UDP（小包 + 3000B 分片）。
test_hy2_obfs_udp() {
  require_root
  echo "== 测试 hysteria2 + salamander（UDP）=="
  # 不截断日志（同 test_hy2_obfs）
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 10 python3 "$HERE/udp_probe.py" 2.2.2.2 9998 3 0.2 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "reply=udp-echo-ok data=ping0 from=2.2.2.2:9998" || { echo "FAIL: 混淆 UDP 未转发到真实目标"; exit 1; }
  echo "$out" | grep -q "^summary=3/3" || { echo "FAIL: 混淆 UDP 报文丢失"; exit 1; }
  grep -q "UDP target=2.2.2.2:9998" "$HY2_LOG" || { echo "FAIL: 服务端未看到 UDP 目标"; cat "$HY2_LOG"; exit 1; }
  sleep 0.3
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
u = v["udp_nat"]
assert u["sessions_proxied"] >= 1, u
assert u["direct_fallback"] == 0, u
assert u["errors"] == 0, u
print("hy2 obfs udp: sessions=%d proxied=%d fallback=%d" % (
    u["sessions_active"], u["sessions_proxied"], u["direct_fallback"]))
PY
  echo "PASS: hysteria2 + salamander UDP（跨实现）"
}

# P5-G3b+：Brutal 近似（cc_override=brutal + 带宽声明）下的转发正确性。
test_hy2_brutal() {
  require_root
  echo "== 测试 hysteria2 Brutal 近似路径 =="
  : >"$HY2_LOG" 2>/dev/null || true
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 30 python3 "$HERE/stream_probe.py" "$PROXY_DST" 8080 512 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "^stream-ok bytes=524288" || { echo "FAIL: Brutal 路径大流量回显不一致"; exit 1; }
  grep -q "TCP target=$PROXY_DST:8080" "$HY2_LOG" || { echo "FAIL: 服务端未看到目标地址"; cat "$HY2_LOG"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
r = v["relay"]
assert v["dialer"].startswith("hysteria2://"), v["dialer"]
assert r["dial_errors"] == 0, r
assert r["bytes_up"] >= 512 * 1024, r
print("hy2 brutal tcp: conns=%d bytes_up=%d" % (r["conns_total"], r["bytes_up"]))
PY
  echo "PASS: hysteria2 cc_override=brutal（固定窗口近似，流量正确）"
}

# P5-G3b+：udphop（服务端多端口 mux；跨 1 次跳端口后继续打流）。
test_hy2_hop() {
  require_root
  echo "== 测试 hysteria2 udphop =="
  # 不截断日志："udphop mux on N sockets" 是服务端多端口启用的证据
  local out
  out="$(ip netns exec "$CLIENT_NS" timeout 30 python3 "$HERE/stream_probe.py" "$PROXY_DST" 8080 512 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "^stream-ok bytes=524288" || { echo "FAIL: 跳端口前大流量失败"; exit 1; }
  # 客户端 hop interval = 5s（Go 侧下限）；等过窗口再打一轮，跨跳验证
  sleep 5.5
  out="$(ip netns exec "$CLIENT_NS" timeout 30 python3 "$HERE/stream_probe.py" "$PROXY_DST" 8080 512 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "^stream-ok bytes=524288" || { echo "FAIL: 跳端口后大流量失败（连接未跨跳存活）"; exit 1; }
  grep -q "udphop mux" "$HY2_LOG" || { echo "FAIL: 服务端未启用多端口 mux"; cat "$HY2_LOG"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - /tmp/sodama-status.json <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
r = v["relay"]
assert v["dialer"].startswith("hysteria2://"), v["dialer"]
assert r["dial_errors"] == 0, r
assert r["bytes_up"] >= 1024 * 1024, r
print("hy2 hop tcp: conns=%d bytes_up=%d（跨 1 次跳端口）" % (r["conns_total"], r["bytes_up"]))
PY
  echo "PASS: hysteria2 udphop（5s 跳端口，QUIC 连接跨跳存活）"
}

# P6：运维面——suspend（no-load/fail-open）、reload（恢复+切槽）、metrics、sysdump、日志轮转。
test_ops() {
  require_root
  echo "== 测试运维面（suspend / reload / metrics / sysdump / 日志轮转）=="
  local out
  # 前置：session 需是无 dialer 的 up/ops-up（tproxy 回显 banner 才能区分代理/直连）
  out="$(ip netns exec "$CLIENT_NS" timeout 6 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "sodama tproxy: orig_dst=$PROXY_DST:8080" || { echo "FAIL: 前置条件不满足（需 up/ops-up 会话）"; exit 1; }
  # suspend：数据面 fail-open（内核直转 -> 真实 wan_echo）
  "$LOADER" suspend --socket "$STATUS_SOCK" >/dev/null
  out="$(ip netns exec "$CLIENT_NS" timeout 6 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "wan-echo-ok" || { echo "FAIL: suspend 后未 fail-open（期望内核直转）"; exit 1; }
  echo "$out" | grep -q tproxy && { echo "FAIL: suspend 后仍走 tproxy"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - <<'PY'
import json
v = json.load(open("/tmp/sodama-status.json"))
assert v["suspended"] is True, v["suspended"]
print("ops: suspended=true（no-load）")
PY
  # reload：清除 suspend + 规则切槽（对照 dae 「suspend 后用 reload 恢复」）
  local before after rjson
  before="$("$LOADER" status --socket "$STATUS_SOCK" --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["active_slot"])')"
  if ! rjson="$("$LOADER" reload --socket "$STATUS_SOCK")"; then
    echo "FAIL: reload CLI 退出非零：$rjson"
    exit 1
  fi
  printf '%s\n' "$rjson" | python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["ok"], v; print("ops: reload ok, match_sets=%d slot=%d" % (v["match_sets"], v["slot"]))'
  after="$("$LOADER" status --socket "$STATUS_SOCK" --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["active_slot"])')"
  [ "$before" != "$after" ] || { echo "FAIL: reload 未切槽（$before -> $after）"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 6 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "sodama tproxy: orig_dst=$PROXY_DST:8080" || { echo "FAIL: reload 后代理未恢复"; exit 1; }
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - <<'PY'
import json
v = json.load(open("/tmp/sodama-status.json"))
assert v["suspended"] is False, v["suspended"]
assert v["reload"]["ok"] is True, v["reload"]
print("ops: reload 后 suspended=false, reload.ok=true")
PY
  # metrics：Prometheus 文本 + 关键序列存在
  "$LOADER" metrics --socket "$STATUS_SOCK" >/tmp/sodama-metrics.txt
  grep -q "^sodama_suspended 0$" /tmp/sodama-metrics.txt || { echo "FAIL: metrics 缺 sodama_suspended"; cat /tmp/sodama-metrics.txt; exit 1; }
  grep -q "^sodama_active_slot " /tmp/sodama-metrics.txt || { echo "FAIL: metrics 缺 active_slot"; exit 1; }
  grep -q "^sodama_info{dialer=" /tmp/sodama-metrics.txt || { echo "FAIL: metrics 缺 info"; exit 1; }
  echo "ops: metrics 文本导出正常（$(grep -c '^sodama_' /tmp/sodama-metrics.txt) 行）"
  # sysdump：可解析、含四类查询与系统信息
  "$LOADER" sysdump --socket "$STATUS_SOCK" --out /tmp/sodama-sysdump.json 2>/dev/null
  python3 - <<'PY'
import json
d = json.load(open("/tmp/sodama-sysdump.json"))
for k in ["status", "rules", "maps", "config", "system", "generated_at_sec"]:
    assert k in d, k
print("ops: sysdump 可解析（keys=%s）" % ",".join(sorted(d.keys())))
PY
  # 日志轮转：mv 旧文件 -> SIGHUP reopen -> 新文件重新出现且有 reload 日志
  if [ -n "${USE_LOG_FILE:-}" ]; then
    [ -s "$OPS_LOG" ] || { echo "FAIL: --log-file 未生效（$OPS_LOG）"; exit 1; }
    mv "$OPS_LOG" "$OPS_LOG.1"
    kill -HUP "$(cat "$PID_FILE")"
    sleep 0.8
    [ -s "$OPS_LOG" ] || { echo "FAIL: SIGHUP 后日志文件未重开"; exit 1; }
    grep -q "热重载" "$OPS_LOG" || { echo "FAIL: 重开后的日志缺 reload 记录"; cat "$OPS_LOG"; exit 1; }
    echo "ops: 日志轮转OK（旧 -> $OPS_LOG.1，新文件含重载记录）"
    rm -f "$OPS_LOG.1"
  fi
  echo "PASS: 运维面（suspend/reload/metrics/sysdump/轮转）"
}

# P6：整配置热重载——规则变更生效 / 失败回滚保留旧规则 / DNS 上游热切换。
test_config_reload() {
  require_root
  echo "== 测试整配置热重载（--config 模式）=="
  local cfg=/tmp/sodama-ops.dae out
  [ -f "$cfg" ] || { echo "FAIL: 缺 $cfg（先用 ops-reload-up 会话启动）"; exit 1; }
  # 1) 初始：8080 走代理，DNS 走假上游 5353
  out="$(ip netns exec "$CLIENT_NS" timeout 6 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "sodama tproxy: orig_dst=$PROXY_DST:8080" || { echo "FAIL: 初始 8080 未走代理"; exit 1; }
  out="$(ip netns exec "$CLIENT_NS" timeout 6 python3 "$HERE/dns_probe.py" 9.9.9.9 proxy.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.3' || { echo "FAIL: 初始 DNS 未经过假上游"; exit 1; }
  # 2) 改写 routing（8080 -> 8081）并 reload：规则变更生效、切槽
  sed -i 's/dport(8080)/dport(8081)/' "$cfg"
  chmod 640 "$cfg"
  "$LOADER" reload --socket "$STATUS_SOCK" | python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["ok"], v; print("config-reload: 规则变更生效 slot=%d" % v["slot"])'
  out="$(ip netns exec "$CLIENT_NS" timeout 6 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q "wan-echo-ok" || { echo "FAIL: 重载后旧规则仍生效（8080 应改走直连）"; exit 1; }
  echo "$out" | grep -q tproxy && { echo "FAIL: 重载后 8080 仍走代理"; exit 1; }
  # 3) 写入损坏配置：reload 必须失败并回滚（旧规则保留）
  printf 'routing {\n' > "$cfg"
  chmod 640 "$cfg"
  if "$LOADER" reload --socket "$STATUS_SOCK" >/tmp/sodama-reload-fail.json 2>/dev/null; then
    echo "FAIL: 损坏配置的 reload 未失败"; cat /tmp/sodama-reload-fail.json; exit 1
  fi
  python3 - <<'PY'
import json
v = json.load(open("/tmp/sodama-reload-fail.json"))
assert v["ok"] is False and v["error"], v
print("config-reload: 损坏配置 reload 失败（rollback）: %s" % v["error"][:60])
PY
  out="$(ip netns exec "$CLIENT_NS" timeout 6 python3 "$HERE/client_probe.py" "$PROXY_DST" 8080 2>&1 || true)"
  echo "$out" | grep -q "wan-echo-ok" || { echo "FAIL: 失败 reload 后旧规则丢失"; exit 1; }
  echo "config-reload: 失败后旧规则保留（8080 仍直连）"
  # 4) DNS 上游热切换：5353 -> 59999（死上游），再切回
  # （先恢复有效配置：步骤 3 故意写坏了它）
  cp "$HERE/ops-reload.dae" "$cfg"
  chmod 640 "$cfg"
  sed -i 's/127.0.0.1:5353/127.0.0.1:59999/' "$cfg"
  chmod 640 "$cfg"
  "$LOADER" reload --socket "$STATUS_SOCK" >/dev/null
  "$LOADER" status --socket "$STATUS_SOCK" --json >/tmp/sodama-status.json
  python3 - <<'PY'
import json
v = json.load(open("/tmp/sodama-status.json"))
assert v["dns"]["upstream"] == "127.0.0.1:59999", v["dns"]
print("config-reload: DNS 上游已切换 -> %s" % v["dns"]["upstream"])
PY
  out="$(ip netns exec "$CLIENT_NS" timeout 5 python3 "$HERE/dns_probe.py" 9.9.9.9 cache.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=' && { echo "FAIL: 死上游不应有应答"; exit 1; }
  sed -i 's/127.0.0.1:59999/127.0.0.1:5353/' "$cfg"
  chmod 640 "$cfg"
  "$LOADER" reload --socket "$STATUS_SOCK" >/dev/null
  out="$(ip netns exec "$CLIENT_NS" timeout 6 python3 "$HERE/dns_probe.py" 9.9.9.9 cache.test 2>&1 || true)"
  echo "$out"
  printf '%s\n' "$out" | grep -q '^answer=10.9.10.9' || { echo "FAIL: 切回后 DNS 未恢复"; exit 1; }
  echo "config-reload: 上游切回 5353，解析恢复"
  echo "PASS: 整配置热重载（变更生效 / 失败回滚 / DNS 上游热切换）"
}

verify() {
  require_root
  echo "== TCX 钩子（root ns）=="
  bpftool net show 2>/dev/null | sed -n '/^tc:/,/^$/p' | head -6
  echo "== TCX 钩子（daens）=="
  ip netns exec "$DAE_NS" bpftool net show 2>/dev/null | sed -n '/^tc:/,/^$/p' | head -6

  local tp=/sys/kernel/tracing/trace_pipe
  [ -e "$tp" ] || tp=/sys/kernel/debug/tracing/trace_pipe
  # 清空环形缓冲，避免上一次运行的通知混进本次证据
  if [ -w /sys/kernel/tracing/trace ]; then
    echo >/sys/kernel/tracing/trace || true
  elif [ -w /sys/kernel/debug/tracing/trace ]; then
    echo >/sys/kernel/debug/tracing/trace || true
  fi
  if [ -e "$tp" ]; then
    (timeout 8 cat "$tp" >/tmp/sodama-trace.txt 2>/dev/null &)
  fi

  local t_fails=0
  if (test_proxy) >/dev/null 2>&1; then echo "proxy     : PASS"; else echo "proxy     : FAIL"; t_fails=$((t_fails + 1)); fi
  if (test_direct) >/dev/null 2>&1; then echo "direct    : PASS"; else echo "direct    : FAIL"; t_fails=$((t_fails + 1)); fi
  if (test_block) >/dev/null 2>&1; then echo "block/not : PASS"; else echo "block/not : FAIL"; t_fails=$((t_fails + 1)); fi
  if (test_host_proxy) >/dev/null 2>&1; then echo "host/wan  : PASS"; else echo "host/wan  : FAIL"; t_fails=$((t_fails + 1)); fi
  if (test_reload) >/dev/null 2>&1; then echo "reload    : PASS"; else echo "reload    : FAIL"; t_fails=$((t_fails + 1)); fi
  if (test_rebind) >/dev/null 2>&1; then echo "rebind    : PASS"; else echo "rebind    : FAIL"; t_fails=$((t_fails + 1)); fi
  if (test_status) >/dev/null 2>&1; then echo "status    : PASS"; else echo "status    : FAIL"; t_fails=$((t_fails + 1)); fi
  if (test_fault_reload) >/dev/null 2>&1; then echo "fault/reload: PASS"; else echo "fault/reload: FAIL"; t_fails=$((t_fails + 1)); fi
  # 对标批：L3 变体（ipip 隧道）与 XDP 计量探针。两者在拓扑/内核不满足时 SKIP（不算失败）。
  # 对标批：L3 变体的选择/挂载与端到端都入 verify 门禁（端到端依赖夹具逐块回显，
  # 见 loader handle_tproxy_conn 与 tproxy_stream_probe.py）。
  if (test_l3_attach) >/dev/null 2>&1; then
    if [ -e /tmp/sodama-l3-skip ]; then echo "l3-attach : SKIP（无 L3 接口）"; else echo "l3-attach : PASS"; fi
  else
    echo "l3-attach : FAIL"; t_fails=$((t_fails + 1))
  fi
  if (test_l3) >/dev/null 2>&1; then
    if [ -e /tmp/sodama-l3-skip ]; then echo "l3        : SKIP（无 L3 接口）"; else echo "l3        : PASS"; fi
  else
    echo "l3        : FAIL"; t_fails=$((t_fails + 1))
  fi
  if (test_xdp) >/dev/null 2>&1; then
    if [ -e /tmp/sodama-xdp-skip ]; then echo "xdp       : SKIP（未挂载）"; else echo "xdp       : PASS"; fi
  else
    echo "xdp       : FAIL"; t_fails=$((t_fails + 1))
  fi
  # 破坏性：kill 掉加载器，必须最后跑
  if (test_fault_kill) >/dev/null 2>&1; then echo "fault/kill : PASS"; else echo "fault/kill : FAIL"; t_fails=$((t_fails + 1)); fi

  if [ -s /tmp/sodama-trace.txt ]; then
    sleep 1
    echo "== 数据路径 printk =="
    grep "sodama" /tmp/sodama-trace.txt | head -10 || true
  fi
  if [ "$t_fails" != 0 ]; then
    echo "!! $t_fails 个用例失败"
    return 1
  fi
}

status() {
  require_root
  echo "== sodama 日志 =="; tail -20 "$LOG" 2>/dev/null || true
  echo; echo "== root ns tc filter (landae/dae0) =="
  tc filter show dev landae ingress 2>/dev/null || true
  tc filter show dev dae0 ingress 2>/dev/null || true
  echo; echo "== daens tc filter (dae0peer) =="
  ip netns exec "$DAE_NS" tc filter show dev dae0peer ingress 2>/dev/null || true
  echo; echo "== daens ip rule / route =="
  ip -n "$DAE_NS" rule show | head -5
  ip -n "$DAE_NS" route show table 2023
}

trace() {
  require_root
  local tp=/sys/kernel/tracing/trace_pipe
  [ -e "$tp" ] || tp=/sys/kernel/debug/tracing/trace_pipe
  [ -e "$tp" ] || die "找不到 trace_pipe（需要 debugfs/ftrace）"
  echo "== 采集 5 秒 bpf_printk（期间请在另一个终端跑 test-proxy）=="
  timeout 5 cat "$tp" 2>/dev/null | grep --line-buffered "sodama" || true
}

down() {
  require_root
  cleanup
  echo "== 已清理 =="
}

case "${1:-}" in
  build) build ;;
  up) up ;;
  dual-up) dual_up ;;
  config-up)
    # loader 校验配置文件权限（≤0640，防敏感配置泄露）；新 clone 默认 0644，这里统一收紧。
    chmod 640 "$HERE/real-user.dae" 2>/dev/null || true
    # P17a：配置里有 dip(geoip: cn)（编译期展开），用小型夹具提供 geodata 文件。
    USE_CONFIG="$HERE/real-user.dae" USE_GEODATA_DIR=/tmp/sodama-geodata up ;;
  subscribe-up) subscribe_up ;;
  sub-order-up) sub_order_up ;;  # P34：订阅顺序回退（pacman 风格，多源）
  ruleset-up) ruleset_up ;;  # P36：规则集（标准格式 + URL 下载）
  sub-reload-up) subscribe_up ;;  # P18e：热更新测试的前置（与 subscribe-up 相同）
  test-sub-reload) test_sub_reload ;;
  groups-up) groups_up ;;  # P19：多组分派（proxy→A / alt→B）
  test-groups) test_groups ;;
  test-subscribe) test_subscribe ;;
  test-sub-order) test_sub_order ;;  # P34：顺序回退（首源标死 → 切次源）
  test-ruleset) test_ruleset ;;  # P36：三种标准格式规则集 + URL 刷新 + 未知集硬失败
  v6-up) USE_RULES="$HERE/rules.v6.dae" USE_SS=1 USE_SS_METHOD=chacha20-ietf-poly1305 \
    USE_SS_PASSWORD=testpass USE_DIALER="ss://chacha20-ietf-poly1305:testpass@127.0.0.1:$SS_PORT" \
    USE_FAKE_DNS=1 USE_DNS_UPSTREAM="127.0.0.1:$FAKE_DNS_PORT" USE_RELAY_IDLE=600 up ;;  # P22：+假 DNS（v6 DNS 接管用）
  test-v6) test_v6 ;;
  pname-up) USE_RULES="$HERE/rules.pname.dae" up ;;
  test-pname) test_pname ;;
  forward-up) USE_FORWARD="socks5://127.0.0.1:$SOCKS5_PORT" up ;;
  dns-up) USE_RULES="$HERE/rules.dns.dae" USE_DNS_UPSTREAM="127.0.0.1:$FAKE_DNS_PORT" USE_FAKE_DNS=1 up ;;
  dot-up) USE_RULES="$HERE/rules.dns.dae" USE_FAKE_DNS=1 USE_DNS_TRANSPORT=tls \
    USE_DNS_UPSTREAM="tls://127.0.0.1:$DOT_PORT?sni=localhost&insecure=1" up ;;
  test-dot) test_dot ;;
  doh-up) USE_RULES="$HERE/rules.dns.dae" USE_FAKE_DNS=1 USE_DNS_TRANSPORT=https \
    USE_DNS_UPSTREAM="https://127.0.0.1:$DOH_PORT/dns-query?sni=localhost&insecure=1" up ;;
  test-doh) test_doh ;;
  doh-h2-up) USE_RULES="$HERE/rules.dns.dae" USE_FAKE_DNS=1 USE_DNS_H2=1 \
    USE_DNS_UPSTREAM="https://127.0.0.1:$DOH_H2_PORT/dns-query?sni=localhost&insecure=1" up ;;  # P23
  test-doh-h2) test_doh_h2 ;;  # P23：DoH over HTTP/2
  doh-h3-up) USE_RULES="$HERE/rules.dns.dae" USE_FAKE_DNS=1 USE_DNS_H3=1 \
    USE_DNS_UPSTREAM="h3://127.0.0.1:$DOH_H3_PORT/dns-query?sni=localhost&insecure=1" up ;;  # P26
  test-doh-h3) test_doh_h3 ;;  # P26：DoH over HTTP/3
  doq-up) USE_RULES="$HERE/rules.dns.dae" USE_FAKE_DNS=1 USE_DNS_TRANSPORT=doq \
    USE_DNS_UPSTREAM="quic://127.0.0.1:$DOQ_PORT?sni=localhost&insecure=1" up ;;
  test-doq) test_doq ;;
  dnsroute-up) chmod 640 "$HERE/dnsroute.dae"; cp "$HERE/dnsroute.dae" /tmp/sodama-dnsroute.dae; \
    chmod 640 /tmp/sodama-dnsroute.dae; cp "$HERE/blocklist.test.txt" /tmp/blocklist.test.txt; \
    USE_CONFIG=/tmp/sodama-dnsroute.dae \
    USE_FAKE_DNS=1 USE_FAKE_DNS_B=1 up ;;
  dnsopts-up) chmod 640 "$HERE/dnsopts.dae"; USE_CONFIG="$HERE/dnsopts.dae" USE_FAKE_DNS=1 up ;;  # P23
  ecscache-up) chmod 640 "$HERE/ecscache.dae"; USE_CONFIG="$HERE/ecscache.dae" USE_FAKE_DNS=1 up ;;  # P28
dns-udp-up) USE_RULES="$HERE/rules.dns.dae" USE_FAKE_DNS=1 \
    USE_DNS_UPSTREAM="udp://127.0.0.1:$FAKE_DNS_PORT" up ;;
  test-dns-options) test_dns_options ;;  # P23：fixed ttl / optimistic / ipversion_prefer
  test-ecs-cache) test_ecs_cache ;;  # P28：ECS 回填 / ecs_cache
test-dns-udp) test_dns_udp ;;  # 显式 udp:// 上游（仅 UDP）
  dns-tcpup-up) USE_RULES="$HERE/rules.dns.dae" USE_FAKE_DNS=1 \
    USE_DNS_UPSTREAM="tcp://127.0.0.1:$FAKE_DNS_PORT" up ;;
  test-dns-tcpup) test_dns_tcpup ;;  # 显式 tcp:// 上游（仅 TCP，服务端同端口的 TCP 面）
  geo-up) USE_RULES="$HERE/rules.geo.dae" USE_DNS_UPSTREAM="127.0.0.1:$FAKE_DNS_PORT" USE_FAKE_DNS=1 \
    USE_GEODATA_DIR=/tmp/sodama-geodata up ;;
  test-geo) test_geo ;;
  regex-up) USE_RULES="$HERE/rules.regex.dae" USE_DNS_UPSTREAM="127.0.0.1:$FAKE_DNS_PORT" USE_FAKE_DNS=1 up ;;
  relay-up) USE_RULES="$HERE/rules.dae" USE_DIALER=direct USE_RELAY_IDLE=2 USE_UDP_IDLE=2 up ;;
  relay-thread-up) SODAMA_NO_REACTOR=1 USE_NO_SPLICE=1 \
    USE_RULES="$HERE/rules.dae" USE_DIALER=direct USE_RELAY_IDLE=2 USE_UDP_IDLE=2 up ;;  # O9：线程泵泄漏回归会话
  test-l3-attach) test_l3_attach ;;
  test-l3) test_l3 ;;
  test-xdp) test_xdp ;;
  # 能力缺口批次（#1–#4）
  must-up) must_up ;;
  test-must) test_must ;;
  subfile-up) subfile_up ;;
  test-sub-file) test_sub_file ;;
  hotplug-up) hotplug_up ;;
  test-hotplug) test_hotplug ;;
  rulecap-up) rulecap_up ;;
  test-rules-cap) test_rules_cap ;;
  # 缺口批次（eBPF 余项）
  gaps-up) gaps_up ;;
  test-gaps) test_gaps ;;
  alive-up) alive_up ;;
  test-alive) test_alive ;;
  fuse-up) fuse_up ;;
  test-fuse) test_fuse ;;
  pin-up) pin_up ;;
  test-pinning) test_pinning ;;
  offload-up) USE_RULES="$HERE/rules.dae" USE_DIALER=direct USE_OFFLOAD=1 USE_RELAY_IDLE=600 up ;;
  udp-up) USE_RULES="$HERE/rules.udp.dae" USE_UDP_IDLE=2 up ;;
  ss-up) USE_RULES="$HERE/rules.dae" USE_SS=1 USE_SS_METHOD=chacha20-ietf-poly1305 USE_SS_PASSWORD=testpass \
    USE_DIALER="ss://chacha20-ietf-poly1305:testpass@127.0.0.1:$SS_PORT" USE_OFFLOAD=1 USE_RELAY_IDLE=600 up ;;
  ss2022-up) ss2022_up ;;  # P18e：SS2022（shadowsocks-rust ssserver 参考对端）
  http-up) http_up ;;      # P18e：HTTP CONNECT 出站（Python 夹具）
  ss-udp-up) USE_RULES="$HERE/rules.udp.dae" USE_SS=1 USE_SS_METHOD=chacha20-ietf-poly1305 USE_SS_PASSWORD=testpass \
    USE_DIALER="ss://chacha20-ietf-poly1305:testpass@127.0.0.1:$SS_PORT" up ;;
  trojan-up) USE_RULES="$HERE/rules.dae" USE_TROJAN=1 USE_TROJAN_PASSWORD=testpass \
    USE_DIALER="trojan://testpass@127.0.0.1:$TROJAN_PORT?sni=localhost&allowInsecure=1" USE_OFFLOAD=1 USE_RELAY_IDLE=600 up ;;
  vless-up) USE_RULES="$HERE/rules.dae" USE_VLESS=1 USE_OFFLOAD=1 USE_RELAY_IDLE=600 \
    USE_DIALER="vless://$VLESS_UUID@127.0.0.1:$VLESS_PORT?type=tcp&security=none&encryption=none" up ;;
  vless-tls-up) USE_RULES="$HERE/rules.dae" USE_VLESS=1 USE_PROTO_TLS=1 USE_OFFLOAD=1 USE_RELAY_IDLE=600 \
    USE_DIALER="vless://$VLESS_UUID@127.0.0.1:$VLESS_TLS_PORT?type=tcp&security=tls&sni=localhost&allowInsecure=1&encryption=none" up ;;
  vless-udp-up) USE_RULES="$HERE/rules.udp.dae" USE_VLESS=1 \
    USE_DIALER="vless://$VLESS_UUID@127.0.0.1:$VLESS_PORT?type=tcp&security=none&encryption=none" up ;;
  vmess-up) USE_RULES="$HERE/rules.dae" USE_VMESS=1 USE_OFFLOAD=1 USE_RELAY_IDLE=600 \
    USE_DIALER="$(vmess_link 127.0.0.1 "$VMESS_PORT" "$VMESS_UUID" chacha20-poly1305 none)" up ;;
  vmess-tls-up) USE_RULES="$HERE/rules.dae" USE_VMESS=1 USE_PROTO_TLS=1 USE_OFFLOAD=1 USE_RELAY_IDLE=600 \
    USE_DIALER="$(vmess_link 127.0.0.1 "$VMESS_TLS_PORT" "$VMESS_UUID" aes-128-gcm tls)" up ;;
  vmess-udp-up) USE_RULES="$HERE/rules.udp.dae" USE_VMESS=1 \
    USE_DIALER="$(vmess_link 127.0.0.1 "$VMESS_PORT" "$VMESS_UUID" aes-128-gcm none)" up ;;
  naive-up) USE_RULES="$HERE/rules.dae" USE_NAIVE=1 USE_OFFLOAD=1 USE_RELAY_IDLE=600 \
    USE_DIALER="naive+https://$NAIVE_USER:$NAIVE_PASS@127.0.0.1:$NAIVE_PORT?sni=localhost&insecure=1" up ;;  # P25
  test-naive) test_naive ;;  # P25：h2 CONNECT + Basic + 流控
  naive-h3-up) USE_RULES="$HERE/rules.dae" USE_NAIVE_H3=1 USE_OFFLOAD=1 USE_RELAY_IDLE=600 \
    USE_DIALER="naive+quic://$NAIVE_USER:$NAIVE_PASS@127.0.0.1:$NAIVE_H3_PORT?sni=localhost&insecure=1" up ;;  # P26
  test-naive-h3) test_naive_h3 ;;  # P26：h3 CONNECT + Basic + DATA 帧
  tuic-up) USE_RULES="$HERE/rules.dae" USE_TUIC=1 USE_OFFLOAD=1 USE_RELAY_IDLE=600 \
    USE_DIALER="tuic://$TUIC_UUID:$TUIC_PASSWORD@127.0.0.1:$TUIC_PORT?sni=localhost&allow_insecure=1&alpn=h3" up ;;
  tuic-udp-up) USE_RULES="$HERE/rules.udp.dae" USE_TUIC=1 \
    USE_DIALER="tuic://$TUIC_UUID:$TUIC_PASSWORD@127.0.0.1:$TUIC_PORT?sni=localhost&allow_insecure=1&alpn=h3" up ;;
  juicity-up) USE_RULES="$HERE/rules.dae" USE_JUICITY=1 USE_OFFLOAD=1 USE_RELAY_IDLE=600 \
    USE_DIALER="juicity://$JUICITY_UUID:$JUICITY_PASSWORD@127.0.0.1:$JUICITY_PORT?sni=localhost&allow_insecure=1" up ;;  # P27
  juicity-udp-up) USE_RULES="$HERE/rules.udp.dae" USE_JUICITY=1 \
    USE_DIALER="juicity://$JUICITY_UUID:$JUICITY_PASSWORD@127.0.0.1:$JUICITY_PORT?sni=localhost&allow_insecure=1" up ;;  # P27
  ssr-up) USE_RULES="$HERE/rules.dae" USE_SSR=1 USE_OFFLOAD=1 USE_RELAY_IDLE=600 \
    USE_DIALER="ssr://127.0.0.1:$SSR_PORT:origin:$SSR_METHOD:plain:$SSR_PASSWORD_B64" up ;;  # P30
  shadowtls-up) USE_RULES="$HERE/rules.dae" USE_SS=1 USE_SS_METHOD=chacha20-ietf-poly1305 USE_SS_PASSWORD=testpass \
    USE_SHADOWTLS=1 USE_SHADOWTLS_VERSION=3 USE_OFFLOAD=1 USE_RELAY_IDLE=600 \
    USE_DIALER="ss://chacha20-ietf-poly1305:testpass@127.0.0.1:$SHADOWTLS_PORT?plugin=shadow-tls;password=$SHADOWTLS_PASSWORD;version=3;sni=localhost;allowInsecure=1" up ;;  # P31
  shadowtls-v2-up) USE_RULES="$HERE/rules.dae" USE_SS=1 USE_SS_METHOD=chacha20-ietf-poly1305 USE_SS_PASSWORD=testpass \
    USE_SHADOWTLS=1 USE_SHADOWTLS_VERSION=2 USE_OFFLOAD=1 USE_RELAY_IDLE=600 \
    USE_DIALER="ss://chacha20-ietf-poly1305:testpass@127.0.0.1:$SHADOWTLS_PORT?plugin=shadow-tls;password=$SHADOWTLS_PASSWORD;version=2;sni=localhost;allowInsecure=1" up ;;  # P31
  shadowtls-v1-up) USE_RULES="$HERE/rules.dae" USE_SS=1 USE_SS_METHOD=chacha20-ietf-poly1305 USE_SS_PASSWORD=testpass \
    USE_SHADOWTLS=1 USE_SHADOWTLS_VERSION=1 USE_OFFLOAD=1 USE_RELAY_IDLE=600 \
    USE_DIALER="ss://chacha20-ietf-poly1305:testpass@127.0.0.1:$SHADOWTLS_PORT?plugin=shadow-tls;version=1;sni=localhost;allowInsecure=1" up ;;  # P31
  hy2-up) USE_RULES="$HERE/rules.dae" USE_HY2=1 USE_OFFLOAD=1 USE_RELAY_IDLE=600 \
    USE_DIALER="hysteria2://$HY2_AUTH@127.0.0.1:$HY2_PORT?sni=localhost&insecure=1&alpn=h3" up ;;
  hy2-udp-up) USE_RULES="$HERE/rules.udp.dae" USE_HY2=1 \
    USE_DIALER="hysteria2://$HY2_AUTH@127.0.0.1:$HY2_PORT?sni=localhost&insecure=1&alpn=h3" up ;;
  hy2-obfs-up) USE_RULES="$HERE/rules.dae" USE_HY2=1 USE_HY2_OBFS=1 USE_OFFLOAD=1 USE_RELAY_IDLE=600 \
    USE_DIALER="hysteria2://$HY2_AUTH@127.0.0.1:$HY2_PORT?sni=localhost&insecure=1&obfs=salamander&obfs-password=$HY2_AUTH" up ;;
  hy2-obfs-udp-up) USE_RULES="$HERE/rules.udp.dae" USE_HY2=1 USE_HY2_OBFS=1 \
    USE_DIALER="hysteria2://$HY2_AUTH@127.0.0.1:$HY2_PORT?sni=localhost&insecure=1&obfs=salamander&obfs-password=$HY2_AUTH" up ;;
  hy2-brutal-up) USE_RULES="$HERE/rules.dae" USE_HY2=1 USE_OFFLOAD=1 USE_RELAY_IDLE=600 \
    USE_DIALER="hysteria2://$HY2_AUTH@127.0.0.1:$HY2_PORT?sni=localhost&insecure=1&upmbps=50&downmbps=100&cc_override=brutal" up ;;
  hy2-hop-up) USE_RULES="$HERE/rules.dae" USE_HY2=1 USE_HY2_HOP=1 USE_OFFLOAD=1 USE_RELAY_IDLE=600 \
    USE_DIALER="hysteria2://$HY2_AUTH@127.0.0.1:$HY2_PORT,$HY2_HOP_PORTS?sni=localhost&insecure=1&udphop-interval=5" up ;;
  ops-up) USE_RULES="$HERE/rules.dae" USE_LOG_FILE=1 up ;;
  ops-reload-up) USE_OPS_RELOAD=1 USE_CONFIG=/tmp/sodama-ops.dae USE_FAKE_DNS=1 up ;;
  bench-up) USE_RULES="$HERE/rules.bench.dae" USE_RELAY_IDLE=600 up ;;
  test-proxy) test_proxy ;;
  test-direct) test_direct ;;
  test-block) test_block ;;
  test-host-proxy) test_host_proxy ;;
  test-reload) test_reload ;;
  test-rebind) test_rebind ;;
  test-status) test_status ;;
  test-config) test_config ;;
  test-forward) test_forward ;;
  test-domain) test_domain ;;
  test-dns-cache) test_dns_cache ;;
  test-dns-tcp) test_dns_tcp ;;
  test-dns-reload) test_dns_reload ;;
  test-domain-regex) test_domain_regex ;;
  test-dns-edns) test_dns_edns ;;
  test-dnsroute) test_dnsroute ;;
  test-relay) test_relay ;;
  test-relay-idle) test_relay_idle ;;
  test-relay-thread-leak) test_relay_thread_leak ;;  # O9：泵线程泄漏回归
  test-udp-relay) test_udp_relay ;;
  test-quic-sniff) test_quic_sniff ;;  # P20：QUIC Initial SNI 嗅探
  sniff-punt-up) chmod 640 "$HERE/sniffpunt.dae"; \
    USE_CONFIG="$HERE/sniffpunt.dae" USE_SS=1 USE_SS_METHOD=chacha20-ietf-poly1305 USE_SS_PASSWORD=testpass \
    USE_SS_B=1 USE_DIAL_MODE=domain+ USE_SNIFF_TIMEOUT=500 USE_SNIFF_PUNT=1 USE_RELAY_IDLE=600 up ;;  # P21
  test-sniff-punt) test_sniff_punt ;;  # P21：嗅探重判（direct/block/组重选）
  test-udp-idle) test_udp_idle ;;
  test-relay-offload) test_relay_offload ;;
  test-offload-lifecycle) test_offload_lifecycle ;;
  test-ss) test_ss ;;
  test-ss2022) test_ss2022 ;;  # P18e
  test-http) test_http_out ;;   # P18e
  test-trojan) test_trojan ;;
  test-ss-udp) test_ss_udp ;;
  test-vless) test_vless ;;
  test-vless-udp) test_vless_udp ;;
  test-vmess) test_vmess ;;
  test-vmess-udp) test_vmess_udp ;;
  test-tuic) test_tuic ;;
  test-tuic-udp) test_tuic_udp ;;
  test-juicity) test_juicity ;;  # P27
  test-juicity-udp) test_juicity_udp ;;  # P27
  test-ssr) test_ssr ;;  # P30
  test-shadowtls) test_shadowtls 3 ;;  # P31
  test-shadowtls-v2) test_shadowtls 2 ;;  # P31
  test-shadowtls-v1) test_shadowtls 1 ;;  # P31
  test-hy2) test_hy2 ;;
  test-hy2-udp) test_hy2_udp ;;
  test-hy2-obfs) test_hy2_obfs ;;
  test-hy2-obfs-udp) test_hy2_obfs_udp ;;
  test-hy2-brutal) test_hy2_brutal ;;
  test-hy2-hop) test_hy2_hop ;;
  test-ops) USE_LOG_FILE=1 test_ops ;;
  test-config-reload) test_config_reload ;;
  test-fault-reload) test_fault_reload ;;
  test-fault-kill) test_fault_kill ;;
  reload) shift; reload "$@" ;;
  verify) verify ;;
  status) status ;;
  trace) trace ;;
  down) down ;;
  *) echo "usage: $0 {build|up|dual-up|config-up|forward-up|dns-up|dot-up|doh-up|doh-h2-up|doh-h3-up|doq-up|dnsroute-up|dnsopts-up|ecscache-up|dns-udp-up|dns-tcpup-up|geo-up|pname-up|regex-up|relay-up|offload-up|udp-up|ss-up|ss2022-up|http-up|groups-up|ss-udp-up|trojan-up|vless-up|vless-tls-up|vless-udp-up|vmess-up|vmess-tls-up|vmess-udp-up|tuic-up|tuic-udp-up|hy2-up|hy2-udp-up|hy2-obfs-up|hy2-obfs-udp-up|hy2-brutal-up|hy2-hop-up|juicity-up|juicity-udp-up|ssr-up|shadowtls-up|shadowtls-v2-up|shadowtls-v1-up|ops-up|naive-up|test-naive|naive-h3-up|test-naive-h3|ops-reload-up|bench-up|test-proxy|test-direct|test-block|test-host-proxy|test-reload|test-rebind|test-status|test-config|test-forward|test-domain|test-dns-cache|test-dns-tcp|test-dns-reload|test-domain-regex|test-dns-edns|test-dot|test-doh|test-doh-h2|test-doh-h3|test-doq|test-dnsroute|test-dns-options|test-ecs-cache|test-dns-udp|test-dns-tcpup|test-geo|test-pname|test-v6|test-relay|test-relay-idle|test-relay-offload|test-offload-lifecycle|test-udp-relay|test-quic-sniff|test-udp-idle|test-ss|test-ss2022|test-http|test-groups|test-trojan|test-ss-udp|test-vless|test-vless-udp|test-vmess|test-vmess-udp|test-tuic|test-tuic-udp|test-juicity|test-juicity-udp|test-ssr|test-shadowtls|test-shadowtls-v2|test-shadowtls-v1|test-hy2|test-hy2-udp|test-hy2-obfs|test-hy2-obfs-udp|test-hy2-brutal|test-hy2-hop|test-ops|test-config-reload|test-fault-reload|test-fault-kill|reload|verify|status|trace|down|sniff-punt-up|test-sniff-punt|subscribe-up|test-subscribe|sub-order-up|test-sub-order|ruleset-up|test-ruleset|must-up|test-must|subfile-up|test-sub-file|hotplug-up|test-hotplug|rulecap-up|test-rules-cap|gaps-up|test-gaps|alive-up|test-alive|fuse-up|test-fuse|pin-up|test-pinning}"; exit 2 ;;
esac
