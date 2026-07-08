#!/bin/bash

echo "=== 🚀 Starting Automatic Recon Tools Installation ==="

# به‌روزرسانی پکیج‌ها و نصب پیش‌نیازها
sudo apt-get update && sudo apt-get install -y python3-pip

# ۱. نصب ابزارهای رسمی ProjectDiscovery با گو (شامل ساب‌فایندر، کاتانا و نوکلئای)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# ۲. نصب سایر ابزارهای ریکان با گو
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/owasp-amass/amass/v4/...@latest

# ۳. نصب ابزارهای مبتنی بر پایتون
pip3 install uro --break-system-packages

# ۴. نصب ابزار x8 (دانلود مستقیم باینری سورس لینوکس)
wget https://github.com/ShuBoHao/x8/releases/download/v4.3.0/x8-linux-amd64.tar.gz
tar -xvf x8-linux-amd64.tar.gz
sudo mv x8 /usr/local/bin/
rm x8-linux-amd64.tar.gz

# ۵. نصب ابزار fallparams
go install -v github.com/0xY9/fallparams@latest 2>/dev/null || echo "[!] check fallparams go repo path"

# ۶. انتقال تمام باینری‌های گو به مسیر اصلی سیستم
sudo cp ~/go/bin/* /usr/local/bin/ 2>/dev/null

# 💥 ۷. دانلود و آپدیت خودکار تمپلیت‌های Nuclei (بسیار مهم)
/usr/local/bin/nuclei -update-templates --silent

echo "=== ✔ All Tools (including Nuclei & Templates) Loaded & Ready to Hunt! ==="