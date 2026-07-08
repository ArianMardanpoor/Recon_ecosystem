#!/usr/bin/env python3
import sys, os, requests, re
from urllib.parse import urlparse

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import Programs, bulk_upsert_subdomains, current_time

class colors:
    Gray = "\033[90m"
    Reset = "\033[0m"

def fetch_wayback(domain):
    # استفاده از matchType=domain برای دریافت تمام ساب‌دامین‌ها و مسیرها
    url = f"http://web.archive.org/cdx/search/cdx?url={domain}&matchType=domain&output=json&fl=original&collapse=urlkey"
    print(f"{colors.Gray}[{current_time()}] Querying Wayback Machine CDX for {domain}...{colors.Reset}")
    
    try:
        response = requests.get(url, timeout=45)
        if response.status_code == 200:
            results = response.json()
            if len(results) > 1:
                subs = set()
                for item in results[1:]:
                    original_url = item[0]
                    try:
                        # پارس کردن دقیق URL
                        parsed = urlparse(original_url)
                        hostname = parsed.hostname
                        if hostname and hostname.endswith(domain):
                            subs.add(hostname.lower())
                    except:
                        continue
                return list(subs)
    except Exception as e:
        print(f"[{current_time()}] Wayback Machine Error: {e}")
        
    return []

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"[{current_time()}] Usage: python3 watch_waybackurls.py <domain>")
        sys.exit(1)
        
    domain = sys.argv[1]
    program = Programs.objects(scopes__in=[domain]).first()

    if program:
        print(f"[{current_time()}] Running Wayback module for {domain}")
        subs = fetch_wayback(domain)
        print(f"{colors.Gray}[{current_time()}] Wayback found {len(subs)} subdomains for {domain}{colors.Reset}")
        if subs:
            bulk_upsert_subdomains(program.program_name, subs, "wayback")
    else:
        print(f"[{current_time()}] Scope for {domain} does not exist in watchtower")
