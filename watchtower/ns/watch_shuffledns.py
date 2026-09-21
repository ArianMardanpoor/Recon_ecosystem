#!/usr/bin/env python3
"""
watch_shuffledns.py
--------------------
جایگزین (اختیاری و مجزا از) watch_ns.py برای resolve کردن ساب‌دامین‌های
یک scope تکی، با استفاده از shuffledns + massdns (به‌جای dnsx دستی +
wildcard_filter.py). منطق مشترک resolve در utils/shuffledns_helper.py
است تا نسخه all (watch_shuffledns_all.py) هم از همان کد استفاده کند.

معادل دستور دستی:
    shuffledns -list walmart-subs.txt -d wal-mart.com -r ~/.resolvers \
        -m $(which massdns) -mode resolve -t 10 -silent

بعد از resolve، به صورت خودکار watch_http.py را روی همان scope اجرا
می‌کند تا فلو subdomains -> live -> http در یک اجرا کامل شود.

به‌صورت پیش‌فرض از ۳ resolver ثابت کاربر استفاده می‌شود (تعریف‌شده در
utils/shuffledns_helper.py: FIXED_RESOLVERS)؛ در صورت نیاز با --resolvers
می‌توان فایل resolver دیگری را جایگزین کرد.

استفاده:
    python3 watch_shuffledns.py <domain>
    python3 watch_shuffledns.py <domain> --resolvers /path/to/custom_resolvers.txt
    python3 watch_shuffledns.py <domain> --skip-http
"""

import sys
import os
import argparse
import subprocess

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import Subdomains, upsert_live, current_time
from utils.shuffledns_helper import resolve_with_shuffledns, FIXED_RESOLVERS


class colors:
    Gray = "\033[90m"
    Green = "\033[92m"
    Reset = "\033[0m"


def run_http_followup(domain):
    """صدا زدن خودکار watch_http.py روی همون scope، بلافاصله بعد از resolve."""
    http_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "http", "watch_http.py")
    http_script = os.path.normpath(http_script)

    if not os.path.exists(http_script):
        print(f"[{current_time()}] [!] watch_http.py not found at {http_script}, skipping httpx follow-up", file=sys.stderr)
        return

    print(f"{colors.Gray}[{current_time()}] Chaining into watch_http.py for {domain}...{colors.Reset}")
    try:
        subprocess.run([sys.executable, http_script, domain], check=False)
    except Exception as e:
        print(f"[{current_time()}] [!] Failed to launch watch_http.py: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Resolve subdomains with shuffledns/massdns (built-in wildcard filtering), then chain into httpx."
    )
    parser.add_argument("domain", help="Scope/domain to resolve (as stored in Subdomains.scope)")
    parser.add_argument("--resolvers", default=None,
                         help=f"Path to a custom resolvers file. Default: fixed built-in "
                              f"resolvers ({', '.join(FIXED_RESOLVERS)})")
    parser.add_argument("--skip-http", action="store_true",
                         help="Only resolve + upsert_live, do not chain into watch_http.py")
    args = parser.parse_args()

    domain = args.domain.strip()
    subdomains = Subdomains.objects(scope=domain)

    if not subdomains:
        print(f"[{current_time()}] No subdomains found for scope: {domain}")
        return

    subdomain_list = [s.subdomain for s in subdomains]
    print(f"[{current_time()}] Running shuffledns module for {domain} "
          f"({len(subdomain_list)} candidate subdomains)")

    live_map = resolve_with_shuffledns(subdomain_list, domain, args.resolvers)

    if not live_map:
        print(f"[{current_time()}] shuffledns completed for {domain} - 0 live "
              f"(or resolution failed, see errors above)")
        return

    upserted = 0
    for host, ips in live_map.items():
        upsert_live({
            "subdomain": host,
            "scope": domain,
            "ips": ips,
            "cdn": "",
        })
        upserted += 1

    print(f"{colors.Green}[{current_time()}] {domain}: {upserted} genuine live subdomains "
          f"upserted (wildcard filtering handled internally by shuffledns/massdns){colors.Reset}")
    print(f"[{current_time()}] shuffledns module completed for {domain}")

    if not args.skip_http:
        run_http_followup(domain)


if __name__ == "__main__":
    main()