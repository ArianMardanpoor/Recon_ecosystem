#!/usr/bin/env python3
import sys, os, requests

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import Programs, bulk_upsert_subdomains, current_time

# لود کردن API Key و Secret
try:
    import config
    CENSYS_API_ID = getattr(config, 'CENSYS_API_ID', os.getenv("CENSYS_API_ID"))
    CENSYS_API_SECRET = getattr(config, 'CENSYS_API_SECRET', os.getenv("CENSYS_API_SECRET"))
except ImportError:
    CENSYS_API_ID = os.getenv("CENSYS_API_ID")
    CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET")

class colors:
    Gray = "\033[90m"
    Reset = "\033[0m"

def fetch_censys(domain):
    if not CENSYS_API_ID or not CENSYS_API_SECRET:
        print(f"[{current_time()}] Censys Credentials not found. Skipping...")
        return []

    print(f"{colors.Gray}[{current_time()}] Querying Censys Search for {domain}...{colors.Reset}")
    
    url = "https://search.censys.io/api/v2/certificates/search"
    query = f"names: {domain}"
    params = {"q": query, "per_page": 100}
    auth = (CENSYS_API_ID, CENSYS_API_SECRET)
    
    subs = set()
    try:
        response = requests.get(url, params=params, auth=auth, timeout=30)
        if response.status_code == 200:
            data = response.json()
            results = data.get('result', {}).get('hits', [])
            for hit in results:
                names = hit.get('names', [])
                for name in names:
                    if name.endswith(domain) and '*' not in name:
                        subs.add(name.lower())
            return list(subs)
        else:
            print(f"[{current_time()}] Censys API Error: {response.status_code}")
    except Exception as e:
        print(f"[{current_time()}] Censys Error: {e}")
        
    return []

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"[{current_time()}] Usage: python3 watch_censys.py <domain>")
        sys.exit(1)
        
    domain = sys.argv[1]
    program = Programs.objects(scopes__in=[domain]).first()

    if program:
        print(f"[{current_time()}] Running Censys module for {domain}")
        subs = fetch_censys(domain)
        print(f"{colors.Gray}[{current_time()}] Censys found {len(subs)} subdomains for {domain}{colors.Reset}")
        if subs:
            bulk_upsert_subdomains(program.program_name, subs, "censys")
