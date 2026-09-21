#!/usr/bin/env python3
"""
utils/shuffledns_helper.py
---------------------------
منطق مشترک resolve با shuffledns (بک‌اند massdns) که هم توسط
ns/watch_shuffledns.py (تک دامنه) و هم ns/watch_shuffledns_all.py
(همه‌ی برنامه‌ها/scope‌ها) استفاده می‌شود — دقیقاً همان الگویی که
utils/wildcard_filter.py برای watch_ns.py و watch_ns_all.py دارد.

shuffledns با -mode resolve و -d <domain> خودش wildcard filtering
داخلی انجام می‌دهد (با query کردن چند ساب‌دامین رندوم روی هر زون و
حذف زون‌هایی که به‌صورت غیرمنتظره resolve می‌شوند)، پس نیازی به
منطق دستی fake-probe مثل wildcard_filter.py نیست.
"""

import os
import json
import shutil
import tempfile
import sys

from utils.safe_subprocess import run_command_safe

SHUFFLEDNS_TIMEOUT = 900  # ثانیه — لیست‌های بزرگ ممکنه طول بکشه

# ریزالورهای ثابت کاربر — مستقیم hardcode شده به‌جای وابستگی به فایل خارجی.
# توجه: فقط ۳ resolver برای حجم بالای ساب‌دامین کند خواهد بود (massdns
# معمولاً با صدها resolver بهترین کارایی رو داره)، ولی طبق درخواست همین
# سه‌تا استفاده می‌شن.
FIXED_RESOLVERS = [
    "8.8.4.4",
    "129.250.35.251",
    "208.67.222.222",
]


def find_massdns_binary():
    """پیدا کردن باینری massdns روی سیستم (لازم برای -m shuffledns)."""
    return shutil.which("massdns")


def _write_resolvers_file():
    """نوشتن لیست ریزالورهای ثابت در یک فایل موقت برای پاس دادن به -r shuffledns."""
    f = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix="_resolvers.txt")
    for r in FIXED_RESOLVERS:
        f.write(f"{r}\n")
    f.close()
    return f.name


def resolve_with_shuffledns(subdomain_list, domain, resolvers_path=None, timeout=SHUFFLEDNS_TIMEOUT):
    """
    اجرای shuffledns در حالت resolve با بک‌اند massdns برای یک scope/domain.
    -mode resolve + -d باعث می‌شه wildcard filtering داخلی خودش فعال باشه.
    -json برای این‌که IP هر host هم برگرده (لازم برای upsert_live).

    resolvers_path: در صورت عدم ارائه، از FIXED_RESOLVERS (ثابت کاربر) استفاده
    می‌شود؛ در صورت ارائه (مثلاً --resolvers دستی)، همان مسیر فایل به‌کار می‌رود.

    برمی‌گردونه: dict {subdomain: [ips]} برای هرچی genuine resolve شده،
    یا {} در صورت خطا/نبود پیش‌نیازها (massdns/لیست خالی).
    """
    if not subdomain_list:
        return {}

    massdns_bin = find_massdns_binary()
    if not massdns_bin:
        print(f"[!] Error: massdns binary not found in PATH. shuffledns requires -m <massdns_path>. Skipping {domain}.", file=sys.stderr)
        return {}

    cleanup_resolvers = False
    if resolvers_path is None:
        resolvers_path = _write_resolvers_file()
        cleanup_resolvers = True
    elif not os.path.exists(resolvers_path):
        print(f"[!] Error: resolvers file not found at {resolvers_path}. Skipping {domain}.", file=sys.stderr)
        return {}

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        for sub in subdomain_list:
            f.write(f"{sub}\n")
        temp_list_path = f.name

    live_map = {}
    try:
        command = [
            "shuffledns",
            "-list", temp_list_path,
            "-d", domain,
            "-r", resolvers_path,
            "-m", massdns_bin,
            "-mode", "resolve",
            "-t", "10",
            "-json",
            "-silent",
        ]

        result = run_command_safe(command, timeout=timeout)

        if result is None:
            print(f"[!] shuffledns failed or timed out for {domain}", file=sys.stderr)
            return {}

        for line in result:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                # بعضی نسخه‌های shuffledns حتی با -json هم ممکنه خط ساده host
                # چاپ کنن (مثلاً بدون رکورد A) — بدون IP نمی‌تونیم upsert_live
                # بزنیم پس این خطوط رو نادیده می‌گیریم.
                continue

            host = obj.get("host", "")
            # shuffledns معمولاً IPها رو زیر کلید "a" میده (شبیه dnsx)؛
            # بعضی نسخه‌ها "answers" پیچیده‌تر برمی‌گردونن — هر دو رو پوشش می‌دیم.
            ips = obj.get("a") or []
            if not ips and isinstance(obj.get("answers"), list):
                ips = [a.get("data") for a in obj["answers"] if a.get("data")]

            if host:
                live_map[host] = ips

    finally:
        try:
            os.unlink(temp_list_path)
        except Exception:
            pass
        if cleanup_resolvers:
            try:
                os.unlink(resolvers_path)
            except Exception:
                pass

    return live_map