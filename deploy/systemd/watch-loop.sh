#!/bin/bash
# watch-loop.sh
# Runs one full recon cycle (watchtower + xsscanner) and exits.
# systemd (via Restart=on-failure + a sleep loop below) keeps re-running it.
#
# This replaces the "while true; do ... sleep 1800; done" loop from the
# original run_all.sh, since systemd is now responsible for the
# start/stop/restart lifecycle instead of a bash infinite loop + nohup.
#
# EDIT REPO_ROOT below to match your actual deployment path.
set -uo pipefail

REPO_ROOT="/opt/recon-ecosystem"
SLEEP_BETWEEN_CYCLES=1800   # 30 minutes, same cadence as the old script

cd "$REPO_ROOT" || exit 1

while true; do
    LOOP_START=$(date +"%Y-%m-%d %H:%M:%S")
    echo "===================================================="
    echo "[CYCLE] Starting recon cycle at: $LOOP_START"
    echo "===================================================="

    echo "[watchtower] Running watch.sh..."
    (cd "$REPO_ROOT/watchtower" && ./watch.sh)

    echo "[xsscanner] Launching scan..."
    if [ -x "$REPO_ROOT/xsscanner/xsscanner" ]; then
        (cd "$REPO_ROOT/xsscanner" && ./xsscanner)
    else
        echo "[!] $REPO_ROOT/xsscanner/xsscanner binary not found or not executable."
        echo "    Build it first: cd xsscanner && go build -o xsscanner main.go"
    fi

    echo "[CYCLE] Done. Sleeping $SLEEP_BETWEEN_CYCLES seconds before next cycle..."
    sleep "$SLEEP_BETWEEN_CYCLES"
done