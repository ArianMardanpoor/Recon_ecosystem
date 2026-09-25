#!/usr/bin/env python3
import sys, os, requests, json

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import Programs, bulk_upsert_subdomains, current_time

# تلاش برای لود کردن API Key از فایل کانفیگ یا محیط
try:
    import config
    CHAOS_API_KEY = getattr(config, 'CHAOS_API_KEY', os.getenv("CHAOS_API_KEY"))
except ImportError:
    CHAOS_API_KEY = os.getenv("CHAOS_API_KEY")

class colors:
    Gray = "\033[90m"
    Reset = "\033[0m"

def fetch_chaos(domain):
    if not CHAOS_API_KEY:
        print(f"[{current_time()}] Chaos API Key not found. Skipping...")
        return []

    url = f"https://dns.projectdiscovery.io/dns/{domain}/public-recon-data"
    headers = {"Authorization": CHAOS_API_KEY}
    
    print(f"{colors.Gray}[{current_time()}] Querying Chaos API for {domain}...{colors.Reset}")
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code == 200:
            data = response.json()
            subs = set()
            if "subdomains" in data:
                for sub in data["subdomains"]:
                    full_sub = f"{sub}.{domain}" if sub else domain
                    subs.add(full_sub.lower())
            return list(subs)
        elif response.status_code == 401:
            print(f"[{current_time()}] Chaos API: Unauthorized (Check your API Key)")
    except Exception as e:
        print(f"[{current_time()}] Chaos API Error: {e}")
        
    return []

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"[{current_time()}] Usage: python3 watch_chaos.py <domain>")
        sys.exit(1)
        
    domain = sys.argv[1]
    program = Programs.objects(scopes__in=[domain]).first()

    if program:
        print(f"[{current_time()}] Running Chaos module for {domain}")
        subs = fetch_chaos(domain)
        print(f"{colors.Gray}[{current_time()}] Chaos found {len(subs)} subdomains for {domain}{colors.Reset}")
        if subs:
            bulk_upsert_subdomains(program.program_name, subs, "chaos")
