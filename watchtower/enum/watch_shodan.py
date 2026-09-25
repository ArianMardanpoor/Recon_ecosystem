#!/usr/bin/env python3
import sys, os, requests

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import Programs, bulk_upsert_subdomains, current_time

# لود کردن API Key
try:
    import config
    SHODAN_API_KEY = getattr(config, 'SHODAN_API_KEY', os.getenv("SHODAN_API_KEY"))
except ImportError:
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

class colors:
    Gray = "\033[90m"
    Reset = "\033[0m"

def fetch_shodan(domain):
    if not SHODAN_API_KEY:
        print(f"[{current_time()}] Shodan API Key not found. Skipping...")
        return []

    print(f"{colors.Gray}[{current_time()}] Querying Shodan API for {domain}...{colors.Reset}")
    
    # Shodan DNS API برای دریافت ساب‌دامین‌ها
    url = f"https://api.shodan.io/dns/domain/{domain}?key={SHODAN_API_KEY}"
    
    subs = set()
    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            data = response.json()
            subdomains = data.get('subdomains', [])
            for sub in subdomains:
                full_sub = f"{sub}.{domain}"
                subs.add(full_sub.lower())
            return list(subs)
        else:
            print(f"[{current_time()}] Shodan API Error: {response.status_code}")
    except Exception as e:
        print(f"[{current_time()}] Shodan Error: {e}")
        
    return []

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"[{current_time()}] Usage: python3 watch_shodan.py <domain>")
        sys.exit(1)
        
    domain = sys.argv[1]
    program = Programs.objects(scopes__in=[domain]).first()

    if program:
        print(f"[{current_time()}] Running Shodan module for {domain}")
        subs = fetch_shodan(domain)
        print(f"{colors.Gray}[{current_time()}] Shodan found {len(subs)} subdomains for {domain}{colors.Reset}")
        if subs:
            bulk_upsert_subdomains(program.program_name, subs, "shodan")
