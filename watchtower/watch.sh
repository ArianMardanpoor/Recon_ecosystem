#!/bin/zsh
source venv/bin/activate
# توقف اجرای اسکریپت در صورت بروز هرگونه خطای حیاتی در دستورات (جلوگیری از اجرای مراحل بعدی روی دیتای ناقص)
set -e

# آدرس‌دهی مطلق (Absolute Path) برای جلوگیری از خطای پیدا نشدن فایل‌ها
BASE_DIR="/workspaces/Recon_ecosystem/watchtower"
source "$BASE_DIR/venv/bin/activate"

# لاگ کردن با تاریخ
LOG_DIR="$BASE_DIR/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/watchtower_$(date +%Y%m%d_%H%M%S).log"

# --- بخش مدیریت Ctrl+C (Graceful Exit) ---
# این تابع مطمئن می‌شود که اگر Ctrl+C زدی، تمام پروسه‌های پایتون و ابزارهای ریکان زیرمجموعه با خیال راحت بسته شوند
cleanup() {
    echo -e "\n[!] Ctrl+C detected. Shutting down Watchtower gracefully..."
    # غیرفعال کردن محیط مجازی
    deactivate 2>/dev/null
    echo "=== Watchtower Terminated Abnormally at $(date) ===" >> "$LOG_FILE"
    exit 130
}

# گرفتن سیگنال SIGINT (معادل Ctrl+C) و SIGTERM و ارجاع به تابع cleanup
trap cleanup SIGINT SIGTERM
# ------------------------------------------

{
    echo "=== Watchtower Started at $(date) ==="
    
    echo "[+] Syncing programs..."
    python3 "$BASE_DIR/programs/watch_sync_program.py"
    
    # Enumeration
    echo "[+] Running enumeration..."
    python3 "$BASE_DIR/enum/watch_enum_all.py"
    
    # DNS resolution
    echo "[+] Running DNS resolution..."
    python3 "$BASE_DIR/ns/watch_ns_all.py"
    
    # HTTP probing
    echo "[+] Running HTTP probing..."
    python3 "$BASE_DIR/http/watch_http_all.py"
    
    # Nuclei scanning (فعلاً کامنت شده)
    # echo "[+] Running Nuclei..."
    # python3 "$BASE_DIR/nuclei/watch_nuclei_all.py"
    
    echo "=== Watchtower Finished at $(date) ==="
} 2>&1 | tee -a "$LOG_FILE"

# خروج تمیز از محیط مجازی در پایان کار
deactivate 2>/dev/null
