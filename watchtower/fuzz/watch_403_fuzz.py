#!/usr/bin/env python3
"""
watch_403_fuzz.py
------------------
Fuzz کردن ساب‌دامین‌هایی که status_code=403 دارن (پیشنیازش اینه که watch_httpx
یا معادلش قبلا اجرا شده و رکورد Http براشون توی دیتابیس ساخته شده باشه)،
و ذخیره‌ی مسیرهای جالب پیدا شده (چیزی به‌جز کدهای exclude شده) به‌عنوان
finding روی همون Http document — با استفاده از تابع آماده‌ی upsert_scan_findings.

استفاده:
    python3 watch_403_fuzz.py <program_name> [options]

مثال:
    python3 watch_403_fuzz.py whatnot --threads 5 --dirsearch-threads 30
    python3 watch_403_fuzz.py whatnot --scope sub.domain.com --limit 20
"""

import sys
import os
import json
import subprocess
import tempfile
import argparse
import shutil
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "database")))

from database.db import Programs, Http, current_time, upsert_scan_findings


class colors:
    Gray = "\033[90m"
    Green = "\033[92m"
    Yellow = "\033[93m"
    Red = "\033[91m"
    Reset = "\033[0m"


# کدهایی که به‌طور پیش‌فرض exclude می‌شن (همون‌هایی که خودت توی توییت اشاره کردی)
DEFAULT_EXCLUDE_CODES = "403,404,500,400,502,503,429"

# نگاشت status code به سطح اطمینان، برای فیلد confidence توی findings
def status_to_confidence(status_code):
    if status_code == 200:
        return "HIGH"
    if status_code in (301, 302, 307, 308):
        return "MEDIUM"
    return "LOW"


def find_dirsearch_binary():
    """پیدا کردن باینری dirsearch روی سیستم"""
    for candidate in ("dirsearch", "dirsearch.py"):
        path = shutil.which(candidate)
        if path:
            return path
    return None


def run_dirsearch(target_url, dirsearch_bin, wordlist=None, threads=30,
                   exclude_codes=DEFAULT_EXCLUDE_CODES, timeout=600, extra_args=None):
    """
    اجرای امن dirsearch روی یک هدف واحد، با خروجی JSON در یک فایل موقت.
    برمی‌گردونه: لیستی از dict های نتایج (مسیرهایی که با کدهای exclude شده مطابقت نداشتن)
    یا None در صورت خطا.
    """
    tmp_out = tempfile.NamedTemporaryFile(prefix="dirsearch_", suffix=".json", delete=False)
    tmp_out.close()
    out_path = tmp_out.name

    command = [
        dirsearch_bin,
        "-u", target_url,
        "-x", exclude_codes,
        "--random-agent",
        "-t", str(threads),
        "--format", "json",
        "-o", out_path,
        "-q",  # quiet: از پر شدن ترمینال جلوگیری می‌کنه
    ]

    if wordlist:
        command.extend(["-w", wordlist])

    if extra_args:
        command.extend(extra_args)

    try:
        subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )

        if not os.path.exists(out_path) or os.path.getsize(out_path) == 0:
            return []

        with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
            raw = json.load(f)

        # فرمت JSON دیرسرچ: {"info": {...}, "results": [{"url":..,"status":..,"path":..,"content-length":..}, ...]}
        results = raw.get("results", []) if isinstance(raw, dict) else []
        return results

    except subprocess.TimeoutExpired:
        print(f"{colors.Red}[{current_time()}] Timeout fuzzing {target_url}{colors.Reset}")
        return None
    except (json.JSONDecodeError, OSError) as e:
        print(f"{colors.Red}[{current_time()}] Failed to parse dirsearch output for {target_url}: {e}{colors.Reset}")
        return None
    finally:
        try:
            os.remove(out_path)
        except OSError:
            pass


def build_findings(subdomain, results):
    """تبدیل نتایج خام dirsearch به فرمت findings سازگار با upsert_scan_findings"""
    findings = []
    for r in results:
        status = r.get("status")
        path = r.get("path") or r.get("url", "")
        findings.append({
            "parameter": path,
            "discovery_source": "dirsearch_403fuzz",
            "reflection_type": str(status),
            "confidence": status_to_confidence(status),
            "url": r.get("url", f"{subdomain}{path}"),
            "content_length": r.get("content-length") or r.get("length"),
            "found_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })
    return findings


def get_target_subdomains(program_name=None, scope=None, limit=None, status_code=403):
    """کشیدن ساب‌دامین‌هایی با status_code مشخص از کالکشن Http"""
    q = Http.objects(status_code=status_code)
    if program_name:
        q = q.filter(program_name=program_name)
    if scope:
        q = q.filter(scope=scope)
    q = q.order_by("-last_update")
    if limit:
        q = q[:limit]
    return list(q)


def process_target(http_doc, dirsearch_bin, wordlist, dirsearch_threads,
                    exclude_codes, timeout, extra_args):
    subdomain = http_doc.subdomain
    target_url = http_doc.url or f"https://{subdomain}"

    print(f"{colors.Gray}[{current_time()}] Fuzzing: {target_url}{colors.Reset}")

    results = run_dirsearch(
        target_url,
        dirsearch_bin,
        wordlist=wordlist,
        threads=dirsearch_threads,
        exclude_codes=exclude_codes,
        timeout=timeout,
        extra_args=extra_args,
    )

    if results is None:
        return subdomain, 0, "error"

    if not results:
        print(f"{colors.Gray}[{current_time()}] Nothing interesting on {subdomain}{colors.Reset}")
        return subdomain, 0, "clean"

    findings = build_findings(subdomain, results)
    upsert_scan_findings(subdomain, findings, scan_status="findings")

    high_hits = sum(1 for f in findings if f["confidence"] == "HIGH")
    color = colors.Green if high_hits else colors.Yellow
    print(f"{color}[{current_time()}] {subdomain}: {len(findings)} hits found "
          f"({high_hits} HIGH confidence){colors.Reset}")

    return subdomain, len(findings), "findings"


def main():
    parser = argparse.ArgumentParser(description="Fuzz 403 subdomains and store results in Watchtower DB")
    parser.add_argument("program_name", help="نام برنامه در دیتابیس (program_name)")
    parser.add_argument("--scope", default=None, help="محدود کردن فقط به یک scope خاص")
    parser.add_argument("--wordlist", default=None, help="مسیر wordlist دلخواه (پیش‌فرض: wordlist خود dirsearch)")
    parser.add_argument("--limit", type=int, default=None, help="حداکثر تعداد ساب‌دامین برای fuzz کردن")
    parser.add_argument("--threads", type=int, default=3, help="تعداد هدف‌هایی که هم‌زمان fuzz می‌شن (پیش‌فرض: 3)")
    parser.add_argument("--dirsearch-threads", type=int, default=30, help="تعداد thread داخلی هر اجرای dirsearch (پیش‌فرض: 30)")
    parser.add_argument("--exclude-codes", default=DEFAULT_EXCLUDE_CODES, help="کدهای exclude شده، جدا شده با کاما")
    parser.add_argument("--timeout", type=int, default=600, help="حداکثر زمان (ثانیه) برای هر اجرای dirsearch")
    parser.add_argument("--delay", type=float, default=0, help="تاخیر (ثانیه) بین شروع fuzz هر هدف")
    parser.add_argument("--extra-args", nargs=argparse.REMAINDER, default=None,
                         help="آرگومان‌های اضافی که مستقیم به dirsearch پاس داده می‌شن")
    args = parser.parse_args()

    dirsearch_bin = find_dirsearch_binary()
    if not dirsearch_bin:
        print(f"{colors.Red}[{current_time()}] dirsearch not found in PATH. نصبش کن یا مسیرش رو به PATH اضافه کن.{colors.Reset}")
        sys.exit(1)

    program = Programs.objects(program_name=args.program_name).first()
    if not program:
        print(f"{colors.Red}[{current_time()}] Program not found: {args.program_name}{colors.Reset}")
        sys.exit(1)

    targets = get_target_subdomains(
        program_name=args.program_name,
        scope=args.scope,
        limit=args.limit,
    )

    if not targets:
        print(f"{colors.Yellow}[{current_time()}] هیچ ساب‌دامین 403 برای {args.program_name} پیدا نشد.{colors.Reset}")
        sys.exit(0)

    print(f"{colors.Gray}[{current_time()}] {len(targets)} target(s) with status_code=403 found for {args.program_name}{colors.Reset}")

    total_findings = 0
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for doc in targets:
            futures.append(executor.submit(
                process_target,
                doc,
                dirsearch_bin,
                args.wordlist,
                args.dirsearch_threads,
                args.exclude_codes,
                args.timeout,
                args.extra_args,
            ))
            if args.delay:
                time.sleep(args.delay)

        for future in as_completed(futures):
            try:
                subdomain, count, status = future.result()
                total_findings += count
            except Exception as e:
                print(f"{colors.Red}[{current_time()}] Worker error: {e}{colors.Reset}")

    print(f"{colors.Gray}[{current_time()}] Done. Total findings stored: {total_findings}{colors.Reset}")


if __name__ == "__main__":
    main()
