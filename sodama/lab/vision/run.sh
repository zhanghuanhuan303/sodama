#!/usr/bin/env bash
# M3 传输变体集成测试：Xray 服务端（VLESS + TLS/REALITY + xtls-rprx-vision / ws / wss）。
#
# 验证（VISION_SECURITY 选择外层，默认 tls）：
#   tls|reality：1) 内层 TLS 1.3 → 触发双向 XTLS DIRECT（裸 TCP 直通）且 2MB 逐字节一致；
#                2) 内层 TLS 1.2 → 不发 DIRECT，END 模式互通；3) 内层明文 HTTP → END 互通；
#                4) 日志双向上/下行 DIRECT 切换。
#   ws：   VLESS over WebSocket（明文）明文 HTTP 探针；
#   wss：  VLESS over WebSocket + TLS，2MB 逐字节（内层再套 TLS）。
#
# 前置：Xray 二进制（默认 /tmp/xray/xray）：
#   curl -L -o /tmp/xray.zip https://github.com/XTLS/Xray-core/releases/download/v25.9.11/Xray-linux-64.zip
#   mkdir -p /tmp/xray && unzip -o /tmp/xray.zip -d /tmp/xray
#
# 用法：sudo [VISION_SECURITY=tls|reality|ws|wss] lab/vision/run.sh {prepare|test|down|all}
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$(dirname "$HERE")")"
LAB="$ROOT/lab/lab.sh"
LOADER="$ROOT/target/release/sodama"
OBJ="$ROOT/ebpf-rs/target/bpfel-unknown-none/release/sodama-ebpf"
XRAY_BIN="${XRAY_BIN:-/tmp/xray/xray}"
CLIENT_NS=sodama_client
WAN_NS=sodama_wan
UUID=b831381d-6324-4d53-ad4f-8cda48b30811
XRAY_PORT=8545
REALITY_PORT=8546
WS_PORT=8547
WSS_PORT=8548
TLS13_PORT=9443
TLS12_PORT=9444
HTTP_PORT=8081
DIR=/tmp/vision-lab
REALITY_SID=41b9cb10b696
DIALER_TLS="vless://$UUID@10.9.9.2:$XRAY_PORT?type=tcp&security=tls&sni=localhost&allowinsecure=1&flow=xtls-rprx-vision"

die() { echo "!! $*" >&2; exit 1; }
require_root() { [ "$(id -u)" = 0 ] || die "需要 root：sudo $0 $*" ; }
in_client() { ip netns exec "$CLIENT_NS" "$@"; }
in_wan() { ip netns exec "$WAN_NS" "$@"; }

# 按 cmdline 特征清理夹具进程（pidfile 记的是 netns 包装进程，杀不干净）。
kill_fixture() {
  local p cmd
  for p in $(pgrep -x xray) $(pgrep -x python3); do
    [ "$p" = "$$" ] && continue
    cmd="$(tr '\0' ' ' </proc/$p/cmdline 2>/dev/null)"
    case "$cmd" in
      *vision-lab*|*https_target.py*) kill -9 "$p" 2>/dev/null || true ;;
    esac
  done
}

prepare() {
  require_root
  [ -x "$XRAY_BIN" ] || die "缺 Xray：$XRAY_BIN（见脚本头下载说明）"
  [ -x "$LOADER" ] || die "先 cargo build --release"
  mkdir -p "$DIR/www"
  # 确定性 2MB 内容 + 校验和 + hello
  python3 - "$DIR" <<'PY'
import hashlib, os, sys
d = sys.argv[1]
pattern = bytes(range(256)) * 8192  # 2 MiB
open(os.path.join(d, "www", "pattern.bin"), "wb").write(pattern)
open(os.path.join(d, "pattern.sha"), "w").write(hashlib.sha256(pattern).hexdigest() + "\n")
open(os.path.join(d, "www", "hello.txt"), "w").write("vision-hello\n")
PY
  # 自签证书（SAN: localhost/1.1.1.1）
  if [ ! -s "$DIR/cert.pem" ]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -keyout "$DIR/key.pem" -out "$DIR/cert.pem" -days 7 -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:localhost,IP:1.1.1.1" >/dev/null 2>&1
  fi
  # Xray 服务端配置（VLESS + TLS/REALITY + vision；出站 freedom 直连靶站）
  if [ ! -s "$DIR/reality-keys.txt" ]; then
    "$XRAY_BIN" x25519 >"$DIR/reality-keys.txt"
  fi
  local rpriv rpub
  rpriv="$(awk -F': ' '/^PrivateKey:/{print $2}' "$DIR/reality-keys.txt")"
  rpub="$(awk -F': ' '/^Password:/{print $2}' "$DIR/reality-keys.txt")"
  [ -n "$rpriv" ] && [ -n "$rpub" ] || die "x25519 密钥解析失败"
  echo "vless://$UUID@10.9.9.2:$REALITY_PORT?type=tcp&security=reality&sni=localhost&pbk=$rpub&sid=$REALITY_SID&fp=chrome&flow=xtls-rprx-vision" >"$DIR/dialer-reality.txt"
  echo "$DIALER_TLS" >"$DIR/dialer-tls.txt"
  echo "vless://$UUID@10.9.9.2:$WS_PORT?type=ws&security=none&host=localhost&path=%2Fws" >"$DIR/dialer-ws.txt"
  echo "vless://$UUID@10.9.9.2:$WSS_PORT?type=ws&security=tls&sni=localhost&allowinsecure=1&host=localhost&path=%2Fws" >"$DIR/dialer-wss.txt"
  cat >"$DIR/xray-server.json" <<JSON
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "listen": "10.9.9.2",
    "port": $XRAY_PORT,
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "$UUID", "flow": "xtls-rprx-vision"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tlsSettings": {"certificates": [{"certificateFile": "$DIR/cert.pem", "keyFile": "$DIR/key.pem"}]}
    }
  }, {
    "listen": "10.9.9.2",
    "port": $REALITY_PORT,
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "$UUID", "flow": "xtls-rprx-vision"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "dest": "1.1.1.1:$TLS13_PORT",
        "serverNames": ["localhost"],
        "privateKey": "$rpriv",
        "shortIds": ["$REALITY_SID"]
      }
    }
  }, {
    "listen": "10.9.9.2",
    "port": $WS_PORT,
    "protocol": "vless",
    "settings": {"clients": [{"id": "$UUID"}], "decryption": "none"},
    "streamSettings": {"network": "ws", "security": "none", "wsSettings": {"path": "/ws"}}
  }, {
    "listen": "10.9.9.2",
    "port": $WSS_PORT,
    "protocol": "vless",
    "settings": {"clients": [{"id": "$UUID"}], "decryption": "none"},
    "streamSettings": {
      "network": "ws",
      "security": "tls",
      "tlsSettings": {"certificates": [{"certificateFile": "$DIR/cert.pem", "keyFile": "$DIR/key.pem"}]},
      "wsSettings": {"path": "/ws"}
    }
  }],
  "outbounds": [{"protocol": "freedom"}]
}
JSON
  "$LAB" down >/dev/null 2>&1 || true
  kill_fixture
  TOPO_ONLY=1 "$LAB" up
  in_wan python3 "$HERE/https_target.py" "$TLS13_PORT" "$DIR/www" tls13 >"$DIR/https13.log" 2>&1 &
  echo $! >"$DIR/https13.pid"
  in_wan python3 "$HERE/https_target.py" "$TLS12_PORT" "$DIR/www" tls12 >"$DIR/https12.log" 2>&1 &
  echo $! >"$DIR/https12.pid"
  in_wan python3 -m http.server "$HTTP_PORT" --bind 0.0.0.0 --directory "$DIR/www" >"$DIR/http8081.log" 2>&1 &
  echo $! >"$DIR/http8081.pid"
  in_wan "$XRAY_BIN" run -c "$DIR/xray-server.json" >"$DIR/xray.log" 2>&1 &
  echo $! >"$DIR/xray.pid"
  sleep 1.0
  in_wan timeout 3 bash -c ": >/dev/tcp/1.1.1.1/$TLS13_PORT" || die "TLS 靶站未就绪（$DIR/https13.log）"
  timeout 3 bash -c ": >/dev/tcp/10.9.9.2/$XRAY_PORT" || die "Xray 未就绪（$DIR/xray.log）"
  echo "== Vision 夹具就绪（xray :$XRAY_PORT / tls13 :$TLS13_PORT / tls12 :$TLS12_PORT / http :$HTTP_PORT） =="
}

start_loader() {
  for p in $(pgrep -x sodama); do kill -9 "$p"; done
  sleep 0.5
  local sec="${VISION_SECURITY:-tls}"
  local dialer
  dialer="$(cat "$DIR/dialer-$sec.txt")"
  "$LOADER" --ebpf "$OBJ" --lan landae --wan wan \
    --dae0 dae0 --dae0peer dae0peer --daens sodamans \
    --rules "$HERE/rules.dae" --dialer "$dialer" \
    --status-socket /tmp/sodama-status.sock >"$DIR/sodama.log" 2>&1 &
  echo $! >"$DIR/sodama.pid"
  sleep 2.0
  kill -0 "$(cat "$DIR/sodama.pid")" 2>/dev/null || { tail -20 "$DIR/sodama.log"; die "sodama 启动失败"; }
}

test() {
  require_root
  in_wan timeout 3 bash -c ": >/dev/tcp/1.1.1.1/$TLS13_PORT" || die "先 prepare"
  start_loader
  local mode="${VISION_SECURITY:-tls}"
  local ok=0 expect=0
  case "$mode" in
    ws)
      # VLESS over WebSocket（明文）：明文 HTTP 探针
      expect=1
      if in_client timeout 30 curl -sS --max-time 20 "http://1.1.1.1:$HTTP_PORT/hello.txt" | grep -q "vision-hello"; then
        echo "PASS: ws 传输明文 HTTP 互通"
        ok=$((ok + 1))
      else
        echo "FAIL: ws 传输失败"
      fi
      ;;
    wss)
      # VLESS over WebSocket + TLS：2MB 逐字节（内层再套 TLS）
      expect=1
      if in_client timeout 60 curl -sS -k --max-time 45 -o "$DIR/pattern.out" \
          "https://1.1.1.1:$TLS13_PORT/pattern.bin" \
        && diff <(sha256sum "$DIR/pattern.out" | cut -d' ' -f1) "$DIR/pattern.sha" >/dev/null; then
        echo "PASS: wss 传输 2MB 逐字节一致"
        ok=$((ok + 1))
      else
        echo "FAIL: wss 传输失败"
      fi
      ;;
    *)
      expect=4
      # 1) 内层 TLS1.3：2MB 逐字节 + DIRECT 双向
      if in_client timeout 60 curl -sS -k --max-time 45 -o "$DIR/pattern.out" \
          "https://1.1.1.1:$TLS13_PORT/pattern.bin"; then
        if diff <(sha256sum "$DIR/pattern.out" | cut -d' ' -f1) "$DIR/pattern.sha" >/dev/null; then
          echo "PASS: 内层 TLS1.3 2MB 逐字节一致"
          ok=$((ok + 1))
        else
          echo "FAIL: 内容校验和不一致"
        fi
      else
        echo "FAIL: 内层 TLS1.3 请求失败"
      fi
      # 2) 内层 TLS1.2：仍应互通（不发 DIRECT）
      if in_client timeout 30 curl -sS -k --max-time 20 "https://1.1.1.1:$TLS12_PORT/hello.txt" \
          | grep -q "vision-hello"; then
        echo "PASS: 内层 TLS1.2（END 回退）互通"
        ok=$((ok + 1))
      else
        echo "FAIL: 内层 TLS1.2 失败"
      fi
      # 3) 内层明文 HTTP：END 模式
      if in_client timeout 30 curl -sS --max-time 20 "http://1.1.1.1:$HTTP_PORT/hello.txt" \
          | grep -q "vision-hello"; then
        echo "PASS: 内层明文 HTTP 互通"
        ok=$((ok + 1))
      else
        echo "FAIL: 内层明文 HTTP 失败"
      fi
      # 4) DIRECT 切换日志（TLS1.3 路径应出现双向上行/下行至少各 1 次）
      if grep -q "vision: 上行 DIRECT 切换" "$DIR/sodama.log" \
          && grep -q "vision: 下行 DIRECT 切换" "$DIR/sodama.log"; then
        echo "PASS: XTLS DIRECT 双向切换已触发"
        ok=$((ok + 1))
      else
        echo "FAIL: 未观察到双向 DIRECT（$(grep -c 'DIRECT 切换' "$DIR/sodama.log" || true) 条）"
      fi
      ;;
  esac
  echo "== Vision 测试（security=$mode）：$ok/$expect 通过 =="
  [ "$ok" = "$expect" ] || { tail -20 "$DIR/sodama.log"; exit 1; }
}

down() {
  require_root
  for p in $(pgrep -x sodama); do kill -9 "$p"; done
  kill_fixture
  "$LAB" down >/dev/null 2>&1 || true
  echo "== 已清理 =="
}

case "${1:-all}" in
  prepare) prepare ;;
  test) test ;;
  down) down ;;
  all) prepare && test ;;
  *) die "usage: $0 {prepare|test|down|all}" ;;
esac
