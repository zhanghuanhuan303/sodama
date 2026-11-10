#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

# run.sh <rules-file> — compile a sodama routing-rules subset with dae's own
# Go compiler and print the kernel-space match_set dump to stdout.
#
# The dae source tree is never modified: it is copied once (excluding .git)
# into ./dae-work, the harness test file is synced into the copy, and the go
# test runs there. See README.md for the output contract and provenance.
#
# Env:
#   DAE_SRC=/path/to/dae     override the dae checkout to copy (default below)
#   PARITY_RESYNC=1          force a fresh copy of the dae tree
set -eu

PARITY_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DAE_SRC=${DAE_SRC:-$(CDPATH= cd -- "$PARITY_DIR/../../.." && pwd)/dae}
WORK_DIR="$PARITY_DIR/dae-work"

if [ ! -f "$DAE_SRC/go.mod" ]; then
	echo "dae source not found at $DAE_SRC" >&2
	echo "clone it as a sibling of this repo: git clone https://github.com/daeuniverse/dae dae" >&2
	echo "or set DAE_SRC=/path/to/dae" >&2
	exit 2
fi

if [ "$#" -ne 1 ]; then
	echo "usage: $0 <rules-file>" >&2
	exit 2
fi
RULES_FILE=$1
if [ ! -f "$RULES_FILE" ]; then
	echo "rules file not found: $RULES_FILE" >&2
	exit 2
fi
case "$RULES_FILE" in
	/*) ;;
	*) RULES_FILE=$(CDPATH= cd -- "$(dirname -- "$RULES_FILE")" && pwd)/$(basename -- "$RULES_FILE") ;;
esac

# One-time (or forced) copy of the dae tree. --exclude=.git keeps the original
# checkout out of the picture and the copy itself is a plain source tree.
if [ "${PARITY_RESYNC:-0}" = "1" ] || [ ! -d "$WORK_DIR" ]; then
	rm -rf "$WORK_DIR"
	mkdir -p "$WORK_DIR"
	tar -C "$DAE_SRC" --exclude=.git -cf - . | tar -C "$WORK_DIR" -xf -
fi

# Always sync the harness test so edits to it take effect.
cp "$PARITY_DIR/zz_parity_dump_test.go" "$WORK_DIR/control/zz_parity_dump_test.go"

OUT=$(mktemp -p "$PARITY_DIR" .parity-out.XXXXXX)
LOG=$(mktemp -p "$PARITY_DIR" .parity-test-log.XXXXXX)
trap 'rm -f "$OUT" "$LOG"' EXIT INT TERM

if ! (cd "$WORK_DIR" && \
	PARITY_RULES="$RULES_FILE" PARITY_OUT="$OUT" \
	go test -tags dae_stub_ebpf -count=1 -run '^TestParityDump$' ./control >"$LOG" 2>&1); then
	echo "parity test failed:" >&2
	cat "$LOG" >&2
	exit 1
fi

cat "$OUT"
