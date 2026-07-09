#!/bin/bash
set -uo pipefail  # NOTE: not -e — we want to report failures per-step, not die on the first one

REPO_ROOT=$(dirname "$(pwd)")
echo "=== 📍 Current Repo Root: $REPO_ROOT ==="

FAILED_STEPS=()
step() { echo -e "\n=== $1 ==="; }
check() { if [ $? -ne 0 ]; then FAILED_STEPS+=("$1"); echo "[!] FAILED: $1"; fi; }

# Make sure GOPATH/bin and cargo bin are on PATH for the REST of this script run
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin:$HOME/.cargo/bin:/usr/local/bin"

step "[1/7] System deps + pnpm"
sudo apt-get update -qq
sudo apt-get install -y python3-pip python3-venv npm libnss3 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 \
    libasound2t64 2>/dev/null || sudo apt-get install -y libasound2
sudo npm install -g pnpm
check "system deps"

step "[2/7] Go recon tools (subfinder, katana, nuclei, httpx, dnsx, assetfinder, gau, waybackurls)"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
check "projectdiscovery/go tools"

pip3 install uro --break-system-packages
check "uro"

# amass is slow/flaky to build from source on every fresh Codespace — use prebuilt release instead
step "[3/7] amass (prebuilt binary, avoids slow/flaky go install)"
AMASS_VER="v4.2.0"
curl -sSL "https://github.com/owasp-amass/amass/releases/download/${AMASS_VER}/amass_Linux_amd64.zip" -o /tmp/amass.zip \
  && sudo unzip -o -j /tmp/amass.zip "amass_Linux_amd64/amass" -d /usr/local/bin \
  && sudo chmod +x /usr/local/bin/amass
check "amass"

step "[4/7] x8 (Rust) + fallparams"
if ! command -v cargo &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi
if ! command -v x8 &> /dev/null; then
    rm -rf /tmp/x8-build
    git clone --depth 1 https://github.com/sh1yo/x8 /tmp/x8-build
    (cd /tmp/x8-build && cargo build --release && sudo cp ./target/release/x8 /usr/local/bin/)
    rm -rf /tmp/x8-build
fi
check "x8"

go install -v github.com/0xY9/fallparams@latest
check "fallparams"

# copy any freshly-built go binaries into a system-wide path too (belt & suspenders)
sudo cp "$GOPATH"/bin/* /usr/local/bin/ 2>/dev/null || true

step "[5/7] Update nuclei templates"
if command -v nuclei &> /dev/null; then
    nuclei -update-templates -silent || echo "[!] nuclei template update failed (non-fatal)"
else
    echo "[!] nuclei not found on PATH, skipping template update"
    FAILED_STEPS+=("nuclei binary missing")
fi

step "[6/7] Compile xsscanner Go modules"
cd "$REPO_ROOT"
if [ -d "xsscanner" ]; then
    cd xsscanner
    go mod tidy   # safer than go mod download alone if go.mod version drifted
    for bin in nice_passive nice_katana nice_params xssniper xsscanner dom_sink_checker x9; do
        src="${bin}.go"
        [ "$bin" = "xsscanner" ] && src="main.go"
        echo "[+] Building $bin..."
        go build -o "$bin" "$src"
        check "build $bin"
    done
    chmod +x nice_passive nice_katana nice_params xssniper xsscanner dom_sink_checker x9 2>/dev/null
    cd "$REPO_ROOT"
else
    echo "[!] CRITICAL: xsscanner directory not found at $REPO_ROOT/xsscanner"
    FAILED_STEPS+=("xsscanner dir missing")
fi

step "[7/7] Aliases, permissions, Python venv, database"
cat << 'EOF' >> ~/.bashrc

# Watchtower Aliases Automatically Added
export PATH="$PATH:$HOME/go/bin:$HOME/.cargo/bin"
alias watch_sync_programs="python3 ~/watchtower/programs/watch_sync_program.py"
alias watch_subfinder="python3 ~/watchtower/enum/watch_subfinder.py"
alias watch_crtsh="python3 ~/watchtower/enum/watch_crtsh.py"
alias watch_enum_all="python3 ~/watchtower/enum/watch_enum_all.py"
alias watch_abuseipdb="python3 ~/watchtower/enum/watch_abuseipdb.py"
alias watch_ns="python3 ~/watchtower/ns/watch_ns.py"
alias watch_ns_all="python3 ~/watchtower/ns/watch_ns_all.py"
alias watch_http="python3 ~/watchtower/http/watch_http.py"
alias watch_http_all="python3 ~/watchtower/http/watch_http_all.py"
alias watch_nuclei_all="python3 ~/watchtower/nuclei/watch_nuclei_all.py"
EOF

cd "$REPO_ROOT"
chmod +x run_all.sh 2>/dev/null
[ -d "watchtower" ] && chmod +x watchtower/watch.sh 2>/dev/null

if [ -d "watchtower" ]; then
    cd watchtower
    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip -q
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt -q
        check "python requirements"
    fi
    deactivate
    cd "$REPO_ROOT"
else
    echo "[!] CRITICAL: watchtower directory not found at $REPO_ROOT/watchtower"
    FAILED_STEPS+=("watchtower dir missing")
fi

if [ -d "watchtower/database" ] && command -v docker &> /dev/null; then
    # wait for docker daemon (dind feature can take a few seconds to come up)
    for i in $(seq 1 15); do
        docker info &>/dev/null && break
        echo "[..] waiting for docker daemon ($i/15)"
        sleep 2
    done
    cd watchtower/database
    docker compose up --build -d
    check "docker compose"
    cd "$REPO_ROOT"
else
    echo "[!] docker not available or watchtower/database missing — skipping DB container start"
    echo "    (add the docker-in-docker feature to devcontainer.json if you need Mongo in-container)"
fi

echo
echo "=================================================="
if [ ${#FAILED_STEPS[@]} -eq 0 ]; then
    echo "✨ All components installed and compiled successfully!"
else
    echo "⚠️  Setup finished with ${#FAILED_STEPS[@]} failed step(s):"
    printf '   - %s\n' "${FAILED_STEPS[@]}"
    echo "Re-run this script after fixing the above, or run the corresponding block manually."
fi
echo "=================================================="
echo "Run 'source ~/.bashrc' or open a new terminal to get the watch_* aliases and PATH updates."