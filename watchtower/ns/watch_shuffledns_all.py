#!/usr/bin/env python3
"""
watch_shuffledns_all.py
------------------------
معادل watch_ns_all.py ولی به‌جای dnsx + wildcard_filter.py دستی، از
shuffledns + massdns استفاده می‌کند (wildcard filtering داخلی خود
shuffledns، بدون نیاز به fake-probe per parent zone).

روی همه‌ی برنامه‌ها (یا لیست فیلترشده با --program) لوپ می‌زند، هر
scope را جدا resolve می‌کند و genuine live subdomain‌ها را upsert
می‌کند. در پایان — مثل watch.sh که watch_ns_all.py را قبل از
watch_http_all.py صدا می‌زند — این اسکریپت هم به‌صورت خودکار
watch_http_all.py را (با همان فیلتر --program در صورت وجود) در انتها
اجرا می‌کند تا کل فلو subdomains -> live -> http کامل شود.

به‌صورت پیش‌فرض از ۳ resolver ثابت کاربر استفاده می‌شود (تعریف‌شده در
utils/shuffledns_helper.py: FIXED_RESOLVERS)؛ در صورت نیاز با --resolvers
می‌توان فایل resolver دیگری را جایگزین کرد.

استفاده:
    python3 watch_shuffledns_all.py
    python3 watch_shuffledns_all.py --program walmart,acme
    python3 watch_shuffledns_all.py --resolvers /path/to/custom_resolvers.txt
    python3 watch_shuffledns_all.py --skip-http
"""

import sys
import os
import argparse
import subprocess

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import Programs, Subdomains, upsert_live, current_time
from utils.shuffledns_helper import resolve_with_shuffledns, FIXED_RESOLVERS
from utils.cli_helpers import parse_program_filter


class colors:
    Gray = "\033[90m"
    Green = "\033[92m"
    Yellow = "\033[93m"
    Reset = "\033[0m"


def run_http_all_followup(program_filter):
    """صدا زدن خودکار watch_http_all.py بعد از تمام شدن resolve همه‌ی scope‌ها."""
    http_all_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "http", "watch_http_all.py")
    http_all_script = os.path.normpath(http_all_script)

    if not os.path.exists(http_all_script):
        print(f"[{current_time()}] [!] watch_http_all.py not found at {http_all_script}, skipping httpx follow-up", file=sys.stderr)
        return

    cmd = [sys.executable, http_all_script]
    if program_filter:
        cmd.extend(["--program", ",".join(program_filter)])

    print(f"{colors.Gray}[{current_time()}] Chaining into watch_http_all.py...{colors.Reset}")
    try:
        subprocess.run(cmd, check=False)
    except Exception as e:
        print(f"[{current_time()}] [!] Failed to launch watch_http_all.py: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Run shuffledns/massdns resolve for all (or filtered) programs, then chain into httpx."
    )
    parser.add_argument('--program', type=str, default=None,
                         help="Run only for the specified program name(s), comma-separated.")
    parser.add_argument('--resolvers', default=None,
                         help=f"Path to a custom resolvers file. Default: fixed built-in "
                              f"resolvers ({', '.join(FIXED_RESOLVERS)})")
    parser.add_argument('--skip-http', action='store_true',
                         help="Only resolve + upsert_live for all scopes, do not chain into watch_http_all.py")
    args = parser.parse_args()

    program_filter = parse_program_filter(args.program)

    # ۱. واکشی برنامه‌ها از دیتابیس (دقیقاً همون منطق watch_ns_all.py)
    if program_filter:
        print(f"[{current_time()}] Running in filtered mode for programs: {', '.join(program_filter)}")
        programs = Programs.objects(program_name__in=program_filter)

        found_programs = [p.program_name for p in programs]
        for p in program_filter:
            if p not in found_programs:
                print(f"[{current_time()}] [!] Warning: program '{p}' not found in database, skipping")

        if not programs:
            print(f"[{current_time()}] [!] Error: None of the specified programs were found in database.")
            sys.exit(1)
    else:
        print(f"[{current_time()}] Running in full mode (all programs)")
        programs = Programs.objects.all()

    total_upserted = 0

    for program in programs:
        # استخراج اسکوپ‌های واقعی این برنامه از کالکشن Subdomains
        distinct_scopes = Subdomains.objects(program_name=program.program_name).distinct('scope')

        if not distinct_scopes:
            print(f"[{current_time()}] No subdomains found in DB for program: {program.program_name}")
            continue

        for scope in distinct_scopes:
            # فیلتر هم‌زمان روی scope و program_name برای جلوگیری از تداخل
            subdomains = Subdomains.objects(scope=scope, program_name=program.program_name)
            if not subdomains:
                continue

            subdomain_list = [s.subdomain for s in subdomains]
            print(f"[{current_time()}] Running shuffledns for scope: {scope} "
                  f"({len(subdomain_list)} candidate subdomains)")

            live_map = resolve_with_shuffledns(subdomain_list, scope, args.resolvers)

            if not live_map:
                print(f"[{current_time()}] {scope}: 0 live "
                      f"(or resolution failed, see errors above)")
                continue

            for host, ips in live_map.items():
                upsert_live({
                    'subdomain': host,
                    'scope': scope,
                    'ips': ips,
                    'cdn': ''
                })
            total_upserted += len(live_map)

            print(f"{colors.Green}[{current_time()}] {scope}: {len(live_map)} genuine live "
                  f"(wildcard filtering handled internally by shuffledns/massdns){colors.Reset}")

    print(f"[{current_time()}] shuffledns-all completed. Total genuine live subdomains upserted: {total_upserted}")

    if not args.skip_http:
        run_http_all_followup(program_filter)


if __name__ == "__main__":
    main()