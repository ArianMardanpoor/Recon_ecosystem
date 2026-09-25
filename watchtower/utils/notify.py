#!/usr/bin/env python3
import requests
import os
from datetime import datetime
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(BASE_DIR, '.env'))

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID")
HTTPS_PROXY        = os.getenv("HTTPS_PROXY") or os.getenv("https_proxy")

LOG_DIR = os.path.expanduser("~/tel_watch_notif")

def current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ==========================================
# بافر داخلی برای batching
# ==========================================

_new_http_buffer    = []   # آیتم‌های جدید HTTP
_change_http_buffer = []   # تغییرات HTTP
BATCH_SIZE = 20

# ==========================================
# لاگ فیل‌شدن ارسال
# ==========================================

def _log_failed(message: str):
    """ذخیره پیام‌هایی که ارسالشان ناموفق بوده"""
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        log_file = os.path.join(LOG_DIR, datetime.now().strftime("%Y-%m-%d") + ".log")
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"[{current_time()}]\n{message}\n{'─'*60}\n")
        print(f"[{current_time()}] 📁 Failed message logged to {log_file}")
    except Exception as e:
        print(f"[{current_time()}] ⚠️ Could not write log: {e}")

# ==========================================
# ارسال پیام خام به تلگرام
# ==========================================

def send_telegram_message(message: str) -> bool:
    """ارسال یک پیام به تلگرام. در صورت شکست، لاگ می‌زند."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print(f"[{current_time()}] ⚠️ Telegram credentials are not set in .env file!")
        _log_failed(message)
        return False

    url     = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    proxies = {"https": HTTPS_PROXY, "http": HTTPS_PROXY} if HTTPS_PROXY else None

    try:
        response = requests.post(url, json=payload, timeout=10, proxies=proxies)
        if response.status_code == 200:
            print(f"[{current_time()}] 🟢 Telegram notification sent successfully.")
            return True
        else:
            print(f"[{current_time()}] 🔴 Failed to send notification: {response.text}")
            _log_failed(message)
            return False
    except requests.exceptions.RequestException as e:
        print(f"[{current_time()}] 🔴 Exception during Telegram request: {e}")
        _log_failed(message)
        return False

# ==========================================
# Batching — HTTP جدید
# ==========================================

def queue_new_http(program_name: str, url: str, status_code: int,
                   title: str, tech: list, ips: list):
    """یک HTTP جدید را به بافر اضافه می‌کند و در صورت پر شدن، flush می‌کند."""
    _new_http_buffer.append({
        "program_name": program_name,
        "url":          url,
        "status_code":  status_code,
        "title":        title,
        "tech":         tech,
        "ips":          ips,
    })
    if len(_new_http_buffer) >= BATCH_SIZE:
        flush_new_http()


def flush_new_http():
    """ارسال تمام HTTP‌های جدید بافرشده به تلگرام."""
    if not _new_http_buffer:
        return

    items = _new_http_buffer.copy()
    _new_http_buffer.clear()

    header = f"🆕 <b>New HTTP Services Found ({len(items)})</b>\n{'─'*30}\n"
    lines  = []
    for item in items:
        tech_str = ", ".join(item["tech"]) if item["tech"] else "—"
        lines.append(
            f"<code>{item['url']}</code>\n"
            f"  📌 {item['status_code']}  🏷 {item['title'] or '—'}  🔧 {tech_str}\n"
            f"  📋 {item['program_name']}"
        )

    _send_chunked(header + "\n\n".join(lines))


# ==========================================
# Batching — تغییرات HTTP
# ==========================================

def queue_http_change(program_name: str, url: str, changes: list):
    """یک تغییر HTTP را به بافر اضافه می‌کند."""
    _change_http_buffer.append({
        "program_name": program_name,
        "url":          url,
        "changes":      changes,
    })
    if len(_change_http_buffer) >= BATCH_SIZE:
        flush_http_changes()


def flush_http_changes():
    """ارسال تمام تغییرات HTTP بافرشده به تلگرام."""
    if not _change_http_buffer:
        return

    items = _change_http_buffer.copy()
    _change_http_buffer.clear()

    header = f"🔄 <b>HTTP Changes Detected ({len(items)})</b>\n{'─'*30}\n"
    lines  = []
    for item in items:
        change_str = " | ".join(item["changes"])
        lines.append(
            f"<code>{item['url']}</code>\n"
            f"  📝 {change_str}\n"
            f"  📋 {item['program_name']}"
        )

    _send_chunked(header + "\n\n".join(lines))


# ==========================================
# flush همه بافرها — در پایان هر اسکن صدا بزن
# ==========================================

def flush_all():
    """ارسال تمام پیام‌های بافرشده. در پایان watch_http_all.py صدا بزن."""
    flush_new_http()
    flush_http_changes()

# ==========================================
# کمکی: تقسیم پیام بلند به چند بخش
# ==========================================

def _send_chunked(message: str, limit: int = 4000):
    if len(message) <= limit:
        send_telegram_message(message)
        return
    parts = message.split("\n\n")
    chunk = ""
    for part in parts:
        if len(chunk) + len(part) + 2 > limit:
            send_telegram_message(chunk)
            chunk = part
        else:
            chunk += ("\n\n" if chunk else "") + part
    if chunk:
        send_telegram_message(chunk)


# ==========================================
# تست
# ==========================================

if __name__ == "__main__":
    test_msg = "🚨 <b>تست سیستم نوتیفیکیشن Watchtower</b>\n\nمتغیرها با موفقیت از فایل .env خوانده شدند!"
    send_telegram_message(test_msg)