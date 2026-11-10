#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

# 拉取软路由上的 sodama 健康曲线 TSV，并生成 SVG 曲线图。
#
# 采集端在软路由：/root/sodama-health-track.sh（每 60s 写 /root/sodama-health.tsv）
# 本脚本在开发机运行：
#   sh sodama/lab/prod/health-track.sh pull     # 只拉取 → sodama-health.tsv
#   sh sodama/lab/prod/health-track.sh plot     # 只画图 → docs/notes/health-curve.svg
#   sh sodama/lab/prod/health-track.sh all      # 拉取 + 画图
#   sh sodama/lab/prod/health-track.sh status   # 看采集器在远端的状态摘要
#
# 环境变量：HOST、PASS（均必填；HOST 例如 root@192.0.2.10）
set -e

HOST="${HOST:?请设置 HOST=user@host}"
PASS="${PASS:?请通过环境变量提供路由器密码}"
TSV="${TSV:-sodama-health.tsv}"
SVG="${SVG:-docs/notes/health-curve.svg}"

SSH="sshpass -p $PASS ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $HOST"
SCP="sshpass -p $PASS scp -O -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

do_pull() {
  echo "== 拉取 $HOST:/root/sodama-health.tsv → $TSV =="
  $SCP "$HOST":/root/sodama-health.tsv "$TSV"
  echo "   行数：$(wc -l < "$TSV")"
}

do_plot() {
  echo "== 生成 $SVG =="
  python3 "$(dirname "$0")/health-plot.py" "$TSV" "$SVG"
}

case "${1:-all}" in
  pull)   do_pull ;;
  plot)   do_plot ;;
  all)    do_pull; do_plot ;;
  status) $SSH 'sh /root/sodama-health-track.sh show' ;;
  start)  $SSH 'sh /root/sodama-health-track.sh start' ;;
  stop)   $SSH 'sh /root/sodama-health-track.sh stop' ;;
  *) echo "用法: $0 pull|plot|all|status|start|stop"; exit 1 ;;
esac
