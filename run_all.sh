#!/bin/bash

# تعریف رنگ‌ها
CYAN='\033[1;36m'
GREEN='\033[1;32m'
PURPLE='\033[1;35m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}[🚀] Booting Recon Ecosystem Web Interfaces...${NC}\n"

# ==========================================
# ۱. اجرای بک‌اند پایتون (Watchtower API)
# ==========================================
echo -e "${GREEN}[+] Starting Watchtower Backend (app.py on Port 3131)...${NC}"
cd watchtower
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
    nohup python3 app.py > backend_run.log 2>&1 &
    deactivate
else
    nohup python3 app.py > backend_run.log 2>&1 &
fi
cd ..

# ==========================================
# ۲. اجرای فرانت‌اند (Vite on Port 3000)
# ==========================================
echo -e "${GREEN}[+] Starting Watchtower Frontend (Vite on Port 3000)...${NC}"
if [ -d "watchtower-frontend" ]; then
    cd watchtower-frontend
    pnpm install > /dev/null 2>&1
    nohup pnpm run dev > frontend_run.log 2>&1 &
    cd ..
fi

# گزارش وضعیت نهایی آدرس‌ها
echo -e "\n${PURPLE}[✔] Web interfaces fired up successfully!${NC}"
if [ "$CODESPACES" = "true" ]; then
    echo -e "${YELLOW}[!] GitHub Codespaces URLs:${NC}"
    echo -e "   - Watchtower API:  https://${CODESPACE_NAME}-3131.app.github.dev"
    echo -e "   - Frontend (Vite): https://${CODESPACE_NAME}-3000.app.github.dev"
else
    echo -e "   - Watchtower API:  http://localhost:3131"
    echo -e "   - Frontend (Vite): http://localhost:3000"
fi

# ==========================================
# ۳. چرخه بی‌پایان ریکان (Daemon Loop) بدون بیلد اضافه
# ==========================================
echo -e "\n${CYAN}[⚡] Entering Core Recon Loop (Continuous Automation)...${NC}"

while true; do
    LOOP_START=$(date +"%Y-%m-%d %H:%M:%S")
    echo -e "\n${YELLOW}====================================================${NC}"
    echo -e "${YELLOW}[🔄] Starting New Recon Cycle at: $LOOP_START${NC}"
    echo -e "${YELLOW}====================================================${NC}"

    # الف) اجرای واچ‌تاور برای ساب‌دومین و ردیابی هدف‌ها
    echo -e "${GREEN}[🛰️] Executing Watchtower Monitoring System...${NC}"
    cd watchtower
    ./watch.sh
    cd ..
    
    # ب) اجرای سریع XSSniper کامپایل شده (بدون تلف کردن وقت برای بیلد مجدد)
    echo -e "\n${GREEN}[🎯] Watchtower finished. Launching pre-compiled XSSniper scan...${NC}"
    cd xsscanner
    if [ -f "./xsscanner" ]; then
        ./xsscanner
    else
        echo -e "${RED}[!] Core binary ./xsscanner not found! Something went wrong in initial setup.${NC}"
    fi
    cd ..

    # ج) استراحت کوتاه بین دورها (مثلاً ۳۰ دقیقه)
    echo -e "\n${PURPLE}[💤] Cycle completed. Sleeping for 30 minutes before next crawl...${NC}"
    sleep 1800
done