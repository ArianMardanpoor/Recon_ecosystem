#!/bin/bash
# install_tools_vps.sh
# VPS-friendly replacement for .devcontainer/install_tools.sh
#
# Differences from the Codespaces version:
#   - REPO_ROOT is resolved from this script's own location, not from
#     the Codespaces-specific "parent of cwd" assumption.
#   - No dependency on the Codespaces/devcontainer environment at all.
#   - Safe to re-run (idempotent-ish); every step is independent and
#     failures are collected instead of aborting the whole run.
#
# Usage:
#   git clone <your-repo> /opt/recon-ecosystem   (or wherever you like)
#   cd /opt/recon-ecosystem
#   sudo bash deploy/install_tools_vps.sh
#
set -uo pipefail

# Resolve repo root from this script's real location (works no matter
# where you put the repo: /opt, /srv, $HOME, etc.)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
echo "=== 📍 Repo Root: $REPO_ROOT ==="

FAILED_STEPS=()
step() { echo -e "\n=== $1 ==="; }
check() { if [ $? -ne 0 ]; then FAILED_STEPS+=("$1"); echo "[!] FAILED: $1"; fi; }

export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin:$HOME/.cargo/bin:/usr/local/bin"

step "[1/7] System deps + pnpm"
sudo apt-get update -qq
sudo apt-get install -y python3-pip python3-venv npm git curl unzip libnss3 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 \
    libasound2t64 2>/dev/null || sudo apt-get install -y libasound2
sudo npm install -g pnpm
check "system deps"

# Ensure Go is installed (Codespaces devcontainer had a feature for this;
# on a bare VPS we install it manually if missing)
if ! command -v go &> /dev/null; then
    step "[1b/7] Installing Go toolchain"
    GO_VERSION="1.23.4"
    curl -sSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    export PATH="$PATH:/usr/local/go/bin"
    echo 'export PATH="$PATH:/usr/local/go/bin"' | sudo tee -a /etc/profile.d/golang.sh
    check "go install"
fi

step "[2/7] Go recon tools (subfinder, katana, nuclei, httpx, dnsx, gau, waybackurls)"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
check "projectdiscovery/go tools"

pip3 install uro --break-system-packages
check "uro"
# ... after your go build commands ...

# Verify param.txt exists
if [ ! -f "xsscanner/param.txt" ]; then
    echo "[ERROR] xsscanner/param.txt not found!"
    exit 1
else
    echo "[SUCCESS] param.txt verified."
fi
step "[3/7] amass (prebuilt binary)"
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

go install github.com/ImAyrix/fallparams@latest
check "fallparams"

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
    go mod tidy
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

step "[7/7] Aliases, permissions, Python venv"
PROFILE_SNIPPET="$HOME/.watchtower_env"
cat << EOF > "$PROFILE_SNIPPET"
# Watchtower Aliases - managed by install_tools_vps.sh
export PATH="\$PATH:\$HOME/go/bin:\$HOME/.cargo/bin:/usr/local/go/bin"
export WATCHTOWER_REPO_ROOT="$REPO_ROOT"
alias watch_sync_programs="python3 $REPO_ROOT/watchtower/programs/watch_sync_program.py"
alias watch_subfinder="python3 $REPO_ROOT/watchtower/enum/watch_subfinder.py"
alias watch_crtsh="python3 $REPO_ROOT/watchtower/enum/watch_crtsh.py"
alias watch_enum_all="python3 $REPO_ROOT/watchtower/enum/watch_enum_all.py"
alias watch_abuseipdb="python3 $REPO_ROOT/watchtower/enum/watch_abuseipdb.py"
alias watch_ns="python3 $REPO_ROOT/watchtower/ns/watch_ns.py"
alias watch_ns_all="python3 $REPO_ROOT/watchtower/ns/watch_ns_all.py"
alias watch_http="python3 $REPO_ROOT/watchtower/http/watch_http.py"
alias watch_http_all="python3 $REPO_ROOT/watchtower/http/watch_http_all.py"
alias watch_nuclei_all="python3 $REPO_ROOT/watchtower/nuclei/watch_nuclei_all.py"
EOF

if ! grep -q "watchtower_env" ~/.bashrc 2>/dev/null; then
    echo "source $PROFILE_SNIPPET" >> ~/.bashrc
fi

chmod +x "$REPO_ROOT/run_all.sh" 2>/dev/null
[ -d "$REPO_ROOT/watchtower" ] && chmod +x "$REPO_ROOT/watchtower/watch.sh" 2>/dev/null

if [ -d "$REPO_ROOT/watchtower" ]; then
    cd "$REPO_ROOT/watchtower"
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

echo
echo "=================================================="
if [ ${#FAILED_STEPS[@]} -eq 0 ]; then
    echo "✨ All components installed and compiled successfully!"
else
    echo "⚠️  Setup finished with ${#FAILED_STEPS[@]} failed step(s):"
    printf '   - %s\n' "${FAILED_STEPS[@]}"
fi
echo "=================================================="
echo "Repo root recorded at: $REPO_ROOT"
echo "Run 'source ~/.bashrc' or open a new terminal to get watch_* aliases."
echo
echo "Next steps:"
echo "  1. Copy watchtower/.env.example to watchtower/.env and fill in MONGO_URI etc."
echo "  2. Copy watchtower-frontend/.env.example to watchtower-frontend/.env"
echo "  3. Copy xsscanner/.env.example to xsscanner/.env"
echo "  4. Install the systemd units in deploy/systemd/ (see README there)"