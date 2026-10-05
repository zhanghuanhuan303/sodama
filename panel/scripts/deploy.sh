#!/usr/bin/env bash
# 部署到软路由（默认 root@192.0.2.10）：二进制 + 前端 + 配置 + procd
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${HOST:?请设置 HOST=user@host}"
# 密码不落盘：通过环境变量传入（PASS=xxx scripts/deploy.sh）
PASS="${PASS:?请提供路由器密码：PASS=xxx $0}"
SSH="sshpass -p $PASS ssh -o StrictHostKeyChecking=no"
SCP="sshpass -p $PASS scp -o StrictHostKeyChecking=no"

[ -f dist/sodama-panel ] || { echo "先跑 scripts/build-router.sh"; exit 1; }

echo "== 推送二进制与静态资源 =="
$SSH "$HOST" 'mkdir -p /etc/sodama-panel /usr/share/sodama-panel/dist'
# 运行中的可执行文件不能被覆盖（ETXTBSY）：先停服务
$SSH "$HOST" '/etc/init.d/sodama-panel stop >/dev/null 2>&1; sleep 1; true'
$SCP dist/sodama-panel "$HOST":/usr/bin/sodama-panel
tar -C dist/www -cf - . | $SSH "$HOST" 'rm -rf /usr/share/sodama-panel/dist && mkdir -p /usr/share/sodama-panel/dist && tar -C /usr/share/sodama-panel/dist -xf -'

echo "== 配置与 init（已存在则不覆盖 token）=="
$SSH "$HOST" '[ -f /etc/sodama-panel/panel.conf ] || true'
$SCP deploy/panel.conf "$HOST":/tmp/panel.conf.new
$SSH "$HOST" '[ -f /etc/sodama-panel/panel.conf ] || cp /tmp/panel.conf.new /etc/sodama-panel/panel.conf'
$SCP deploy/sodama-panel.init "$HOST":/etc/init.d/sodama-panel
$SSH "$HOST" 'chmod 755 /usr/bin/sodama-panel /etc/init.d/sodama-panel; chmod 640 /etc/sodama-panel/panel.conf; /etc/init.d/sodama-panel enable; /etc/init.d/sodama-panel restart; sleep 2; pgrep -f sodama-panel >/dev/null && echo "面板运行中" || echo "启动失败"'

echo
echo "面板地址： http://${HOST#*@}:8080/"
