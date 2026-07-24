#!/bin/bash

# توقف اجرای اسکریپت در صورت بروز هرگونه خطای حیاتی
set -e

# پیدا کردن مسیر مطلق اسکریپت با سینتکس استاندارد Bash
SCRIPT_PATH="${BASH_SOURCE[0]:-$0}"
BASE_DIR="$(cd "$(dirname "$SCRIPT_PATH")" &> /dev/null && pwd)"

# مدیریت فشردن کلید Ctrl+C (SIGINT) برای خروج امن
trap 'echo -e "\n[!] Ctrl+C detected. Exiting Watchtower pipeline gracefully..."; exit 1' SIGINT SIGTERM

# پارس آرگومان‌های ورودی
PROGRAM_FILTER=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --program)
            PROGRAM_FILTER="$2"
            shift 2
            ;;
        *)
            echo "[!] Unknown argument: $1"
            exit 1
            ;;
    esac
done

echo "[*] Initializing pipeline in $BASE_DIR..."

# فعال کردن محیط مجازی (وابسته به مسیر داینامیک BASE_DIR)
if [ -f "$BASE_DIR/venv/bin/activate" ]; then
    source "$BASE_DIR/venv/bin/activate"
    echo "[+] Virtual environment activated."
else
    echo "[!] ERROR: venv not found. Ensure Dockerfile built it correctly in $BASE_DIR/venv."
    exit 1
fi

# بررسی وجود .env (در دایرکتوری جاری یا در روت پروژه داکر)
ENV_FILE="$BASE_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
    if [ -f "$BASE_DIR/../.env" ]; then
        ENV_FILE="$BASE_DIR/../.env"
    else
        echo "[!] ERROR: .env not found in $BASE_DIR or root directory."
        exit 1
    fi
fi

if ! grep -qE '^MONGO_URI=.+' "$ENV_FILE"; then
    echo "[!] ERROR: MONGO_URI is not set in $ENV_FILE."
    exit 1
fi
echo "[+] Environment variables loaded."

# ایجاد دایرکتوری لاگ‌گیری اصلی در صورت عدم وجود
LOG_DIR="$BASE_DIR/logs"
mkdir -p "$LOG_DIR"

# تابعی برای اجرای اسکریپت‌ها با لاگ‌گیری
run_module() {
    local script_name=$1
    shift  # حذف نام اسکریپت از آرگومان‌ها تا بقیه برای $@ باقی بمانند
    local log_file="$LOG_DIR/${script_name%.py}.log"
    
    # ایجاد خودکار دایرکتوری‌های فرعی لاگ (مثل logs/programs یا logs/enum)
    mkdir -p "$(dirname "$log_file")"
    
    echo "---------------------------------------------------"
    echo "[*] Running $script_name $@..."
    # اجرای اسکریپت پایتون و ذخیره همزمان خروجی در ترمینال و فایل لاگ
    python "$BASE_DIR/$script_name" "$@" 2>&1 | tee -a "$log_file"
    
    # بررسی کد خروج اسکریپت پایتون
    if [ ${PIPESTATUS[0]} -ne 0 ]; then
        echo "[!] ERROR: $script_name failed. Check $log_file for details."
        exit 1
    fi
    echo "[+] Finished $script_name."
}

# اجرای زنجیره‌ای ماژول‌ها به ترتیب
if [ -n "$PROGRAM_FILTER" ]; then
    echo "[*] Running in filtered mode for programs: $PROGRAM_FILTER"
    run_module "programs/watch_sync_program.py" --program "$PROGRAM_FILTER"
    run_module "enum/watch_enum_all.py" --program "$PROGRAM_FILTER"
    run_module "ns/watch_ns_all.py" --program "$PROGRAM_FILTER"
    run_module "http/watch_http_all.py" --program "$PROGRAM_FILTER"
else
    echo "[*] Running in full mode (all programs)"
    run_module "programs/watch_sync_program.py"
    run_module "enum/watch_enum_all.py"
    run_module "ns/watch_ns_all.py"
    run_module "http/watch_http_all.py"
fi

echo "---------------------------------------------------"
echo "[+] All pipeline stages completed successfully."