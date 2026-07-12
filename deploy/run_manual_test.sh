#!/bin/bash
# run_manual_test.sh
#
# Manual/local test runner — NOT for production (use systemd, see deploy/README.md).
#
# Differences from the old run_all.sh:
#   - No $CODESPACES check / no fake github.dev URLs.
#   - No nohup + infinite while-loop — runs everything in the FOREGROUND
#     so you can see output directly and Ctrl+C to stop cleanly.
#   - Runs exactly ONE recon cycle then exits (no auto-repeat), so you can
#     quickly check "does this even start" without committing to a
#     30-minute loop.
#   - Resolves its own path instead of assuming a fixed repo layout.
#
# Usage:
#   bash run_manual_test.sh            # full check: backend + frontend + one recon cycle
#   bash run_manual_test.sh --no-scan  # just start backend+frontend, skip watch.sh/xsscanner
#
set -uo pipefail

CYAN='\033[1;36m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SKIP_SCAN=false
if [ "${1:-}" = "--no-scan" ]; then
    SKIP_SCAN=true
fi

echo -e "${CYAN}[TEST] Manual test run — repo root: $REPO_ROOT${NC}\n"

# Track child PIDs so we can clean them up on exit / Ctrl+C
PIDS=()
cleanup() {
    echo -e "\n${YELLOW}[TEST] Stopping backend/frontend test processes...${NC}"
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null
    done
    wait 2>/dev/null
    echo -e "${GREEN}[TEST] Cleaned up.${NC}"
}
trap cleanup EXIT INT TERM

# ==========================================
# 1. Backend (Flask API) — foreground-ish, but backgrounded so we can
#    also start the frontend and watch both logs from one terminal.
# ==========================================
echo -e "${GREEN}[+] Starting Watchtower Backend (app.py)...${NC}"
if [ ! -d "$REPO_ROOT/watchtower" ]; then
    echo -e "${RED}[!] watchtower/ directory not found. Aborting.${NC}"
    exit 1
fi

cd "$REPO_ROOT/watchtower"
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}[!] watchtower/.env not found — copy .env.example and fill it in first.${NC}"
fi

if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
    python3 app.py 2>&1 | sed "s/^/${CYAN}[backend]${NC} /" &
    PIDS+=($!)
    deactivate
else
    echo -e "${YELLOW}[!] No venv found at watchtower/venv — using system python3.${NC}"
    python3 app.py 2>&1 | sed "s/^/${CYAN}[backend]${NC} /" &
    PIDS+=($!)
fi
cd "$REPO_ROOT"

# Give it a moment, then confirm it's actually up before moving on
sleep 3
if curl -sf http://127.0.0.1:3131/api/health > /dev/null 2>&1; then
    echo -e "${GREEN}[✓] Backend health check passed (http://127.0.0.1:3131/api/health)${NC}"
else
    echo -e "${RED}[!] Backend health check FAILED. Check the [backend] log lines above.${NC}"
fi

# ==========================================
# 2. Frontend (Vite dev server) — dev mode is fine for manual testing;
#    use pnpm build + the systemd unit for anything long-running.
# ==========================================
echo -e "\n${GREEN}[+] Starting Watchtower Frontend (Vite dev server)...${NC}"
if [ -d "$REPO_ROOT/watchtower-frontend" ]; then
    cd "$REPO_ROOT/watchtower-frontend"
    if [ ! -f ".env" ]; then
        echo -e "${YELLOW}[!] watchtower-frontend/.env not found — copy .env.example and fill it in first.${NC}"
    fi
    pnpm install > /dev/null 2>&1
    pnpm run dev 2>&1 | sed "s/^/${CYAN}[frontend]${NC} /" &
    PIDS+=($!)
    cd "$REPO_ROOT"
else
    echo -e "${YELLOW}[!] watchtower-frontend/ not found, skipping.${NC}"
fi

sleep 3
echo -e "\n${GREEN}[✓] Frontend should be reachable at: http://localhost:3000${NC}"
echo -e "${GREEN}[✓] Backend should be reachable at:  http://localhost:3131/api/health${NC}"

# ==========================================
# 3. One recon cycle (optional) — runs in the FOREGROUND so you can
#    actually watch it and Ctrl+C if it's taking too long.
# ==========================================
if [ "$SKIP_SCAN" = true ]; then
    echo -e "\n${YELLOW}[TEST] --no-scan passed, skipping watch.sh/xsscanner.${NC}"
else
    echo -e "\n${CYAN}[+] Running ONE recon cycle (watch.sh)...${NC}"
    if [ -x "$REPO_ROOT/watchtower/watch.sh" ]; then
        (cd "$REPO_ROOT/watchtower" && ./watch.sh)
    else
        echo -e "${YELLOW}[!] watchtower/watch.sh not found or not executable, skipping.${NC}"
    fi

    echo -e "\n${CYAN}[+] Running ONE xsscanner pass...${NC}"
    if [ -x "$REPO_ROOT/xsscanner/xsscanner" ]; then
        (cd "$REPO_ROOT/xsscanner" && ./xsscanner)
    else
        echo -e "${YELLOW}[!] xsscanner binary not found or not executable.${NC}"
        echo -e "    Build it: cd xsscanner && go build -o xsscanner main.go"
    fi
fi

echo -e "\n${GREEN}[TEST] Manual test cycle complete.${NC}"
echo -e "${CYAN}Backend and frontend are still running in the background.${NC}"
echo -e "${CYAN}Press Ctrl+C to stop them and exit.${NC}\n"

# Keep the script alive so backend/frontend stay up until the user is done
# poking at http://localhost:3000 — Ctrl+C triggers cleanup() above.
wait
