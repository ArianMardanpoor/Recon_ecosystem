#!/bin/bash

# تعریف رنگ‌ها
CYAN='\033[1;36m'
GREEN='\033[1;32m'
PURPLE='\033[1;35m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}[🚀] Booting Recon Ecosystem with exact configs...${NC}\n"

# ==========================================
# ۱. اجرای بک‌اند پایتون (Watchtower API)
# ==========================================
echo -e "${GREEN}[+] Starting Watchtower Backend (app.py on Port 3131)...${NC}"
cd watchtower
source venv/bin/activate
nohup python3 app.py > backend_run.log 2>&1 &
deactivate
cd ..

# ==========================================
# ۲. اجرای فرانت‌اند (Vite on Port 3000)
# ==========================================
echo -e "${GREEN}[+] Starting Watchtower Frontend (Vite on Port 3000)...${NC}"
cd watchtower-frontend
nohup pnpm run dev > frontend_run.log 2>&1 &
cd ..

# ==========================================
# ۳. بررسی و کامپایل هوشمند باینری‌های گو
# ==========================================
# اگر باینری اصلی یا ابزار اصلی XSS نباشه، کل پکیج رو بیلد می‌کنه
if [ ! -f "xsscanner/xsscanner" ] || [ ! -f "xsscanner/xssniper" ]; then
    echo -e "${PURPLE}[!] Missing Go binaries. Compiling complete waterfall suite...${NC}"
    cd xsscanner
    go mod download
    
    # بیلد تمام ابزارهای مورد نیاز تابع processTarget
    go build -o nice_passive nice_passive.go
    go build -o nice_katana nice_katana.go
    go build -o nice_params nice_params.go
    go build -o xssniper xssniper.go
    go build -o xsscanner main.go
    
    chmod +x nice_passive nice_katana nice_params xssniper xsscanner
    cd ..
fi

# ==========================================
# گزارش وضعیت نهایی آدرس‌ها
# ==========================================
echo -e "\n${PURPLE}[✔] All components fired up successfully!${NC}"

if [ "$CODESPACES" = "true" ]; then
    echo -e "${YELLOW}[!] GitHub Codespaces detected. Click these forwarded URLs to access:${NC}"
    echo -e "   - Watchtower API:  https://${CODESPACE_NAME}-3131.app.github.dev"
    echo -e "   - Frontend (Vite): https://${CODESPACE_NAME}-3000.app.github.dev"
else
    echo -e "   - Watchtower API:  http://localhost:3131"
    echo -e "   - Frontend (Vite): http://localhost:3000"
fi