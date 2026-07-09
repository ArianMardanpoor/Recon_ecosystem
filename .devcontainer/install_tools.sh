#!/bin/bash

# ذخیره مسیر اصلی مونو-ریپو برای جلوگیری از گم شدن در دایرکتوری‌ها
REPO_ROOT=$(dirname "$(pwd)")
echo "=== 📍 Current Repo Root: $REPO_ROOT ==="

echo "=== 🚀 [1/6] Starting Automatic Recon Tools Installation ==="
# ۱. به‌روزرسانی پکیج‌ها و نصب پیش‌نیازها
sudo apt-get update && sudo apt-get install -y python3-pip npm
sudo npm install -g pnpm

# ۲. نصب ابزارهای رسمی ProjectDiscovery با گو
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# ۳. نصب سایر ابزارهای ریکان با گو و پایتون
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/owasp-amass/amass/v4/...@latest
pip3 install uro --break-system-packages

echo "[+] Installing x8 from source (Rust)..."
# نصب پیش‌نیاز Rust اگر وجود ندارد
if ! command -v cargo &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
fi

# دانلود و بیلد
git clone https://github.com/sh1yo/x8
cd x8
cargo build --release
sudo cp ./target/release/x8 /usr/local/bin/
cd ..
rm -rf x8

# ۵. نصب ابزار fallparams و انتقال تمام باینری‌های گو به مسیر سراسری سیستم
go install -v github.com/0xY9/fallparams@latest 2>/dev/null
sudo cp ~/go/bin/* /usr/local/bin/ 2>/dev/null

# ۶. آپدیت خودکار تمپلیت‌های Nuclei (حالا که در مسیر کپی شده کار می‌کند)
if [ -f "/usr/local/bin/nuclei" ]; then
    /usr/local/bin/nuclei -update-templates --silent
fi


echo "=== 🐹 [2/6] Compiling Custom Go Modules ONE TIME ONLY (xsscanner) ==="
cd "$REPO_ROOT"
if [ -d "xsscanner" ]; then
    cd xsscanner
    go mod download
    echo "[+] Compiling nice_passive..."
    go build -o nice_passive nice_passive.go
    echo "[+] Compiling nice_katana..."
    go build -o nice_katana nice_katana.go
    echo "[+] Compiling nice_params..."
    go build -o nice_params nice_params.go
    echo "[+] Compiling xssniper..."
    go build -o xssniper xssniper.go
    echo "[+] Compiling main core xsscanner..."
    go build -o xsscanner main.go
    chmod +x nice_passive nice_katana nice_params xssniper xsscanner
else
    echo "[!] CRITICAL: xsscanner directory not found at $REPO_ROOT/xsscanner"
fi


echo "=== 📜 [3/6] Injecting Watchtower Aliases into .bashrc ==="
cat << 'EOF' >> ~/.bashrc

# Watchtower Aliases Automatically Added
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


echo "=== 🔑 [4/6] Granting Execution Permissions to Scripts ==="
cd "$REPO_ROOT"
chmod +x run_all.sh 2>/dev/null
if [ -d "watchtower" ]; then
    chmod +x watchtower/watch.sh 2>/dev/null
fi


echo "=== 🐍 [5/6] Setting up Python Virtual Environment (VENV) ==="
cd "$REPO_ROOT"
if [ -d "watchtower" ]; then
    cd watchtower
    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
    else
        echo "[!] requirements.txt not found inside watchtower/"
    fi
    deactivate
else
    echo "[!] CRITICAL: watchtower directory not found at $REPO_ROOT/watchtower"
fi


echo "=== 🐳 [6/6] Starting Database Containers via Docker Compose ==="
cd "$REPO_ROOT"
if [ -d "watchtower/database" ]; then
    cd watchtower/database
    docker compose up --build -d
else
    echo "[!] Docker directory not found, skipping compose up."
fi

cd "$REPO_ROOT"
echo "=== ✨ Fixed & Cleaned! All Components Compiled and Synced! ==="