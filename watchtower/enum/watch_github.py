#!/usr/bin/env python3
import sys, os, requests, re, base64, time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import Programs, bulk_upsert_subdomains, current_time

# لود کردن توکن گیت‌هاب
try:
    import config
    GITHUB_TOKEN = getattr(config, 'GITHUB_TOKEN', os.getenv("GITHUB_TOKEN"))
except ImportError:
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

class colors:
    Gray = "\033[90m"
    Reset = "\033[0m"

def github_search(domain):
    if not GITHUB_TOKEN:
        print(f"[{current_time()}] GitHub Token not found. Skipping...")
        return []

    print(f"{colors.Gray}[{current_time()}] Searching GitHub code for {domain}...{colors.Reset}")
    
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    # جستجوی کوئری برای پیدا کردن ساب‌دامین‌ها در فایل‌های متنی و کد
    query = f'"{domain}"'
    url = f"https://api.github.com/search/code?q={query}"
    
    subs = set()
    try:
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code == 200:
            items = response.json().get('items', [])
            for item in items[:10]: # محدود کردن به ۱۰ فایل اول برای سرعت و جلوگیری از Rate Limit
                file_url = item['url']
                file_res = requests.get(file_url, headers=headers, timeout=15)
                if file_res.status_code == 200:
                    content_b64 = file_res.json().get('content', '')
                    content = base64.b64decode(content_b64).decode('utf-8', errors='ignore')
                    # رگکس برای پیدا کردن ساب‌دامین‌ها
                    found = re.findall(r'(([a-zA-Z0-9\-]+\.)+' + re.escape(domain) + ')', content)
                    for f in found:
                        subs.add(f[0].lower())
                time.sleep(1) # وقفه کوتاه بین درخواست‌ها
            return list(subs)
        elif response.status_code == 403:
            print(f"[{current_time()}] GitHub API: Rate limit exceeded")
    except Exception as e:
        print(f"[{current_time()}] GitHub Error: {e}")
        
    return []

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"[{current_time()}] Usage: python3 watch_github.py <domain>")
        sys.exit(1)
        
    domain = sys.argv[1]
    program = Programs.objects(scopes__in=[domain]).first()

    if program:
        print(f"[{current_time()}] Running GitHub module for {domain}")
        subs = github_search(domain)
        print(f"{colors.Gray}[{current_time()}] GitHub found {len(subs)} subdomains for {domain}{colors.Reset}")
        if subs:
            bulk_upsert_subdomains(program.program_name, subs, "github")
