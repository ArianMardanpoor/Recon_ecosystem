#!/usr/bin/env python3
import sys, os, subprocess, re, requests

# اصلاح مسیر و نحوه ایمپورت مشابه سایر اسکریپت‌ها
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import Programs, upsert_subdomain, current_time

def run_command_zsh(command):
    try:
        result = subprocess.run(["zsh", "-c", command], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[{current_time()}] Error occurred:", result.stderr)
            return False
        
        return result.stdout.splitlines()
    except subprocess.CalledProcessError as exc:
        print("Status : Fail", exc.returncode, exc.output)

class colors:
    Gray = "\033[90m"
    Reset = "\033[0m"

def abuseipdb(domain):
    url = f'https://www.abuseipdb.com/whois/{domain}'
    
    # 🔥 بسیار مهم: افزودن User-Agent مرورگر برای دور زدن فایروال اولیه و جلوگیری از بلاک شدن
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5'
    }
    cookies = {}

    print(f"{colors.Gray}Requesting URL: {url}{colors.Reset}")
    
    try:
        # 🔥 افزودن timeout جهت جلوگیری از هنگ کردن فرآیند اسکن واچ‌تاور
        response = requests.get(url=url, headers=headers, cookies=cookies, timeout=15)
        
        if response.status_code != 200:
            print(f"[{current_time()}] Error occurred: {response.status_code} - {response.reason}")
            return []

        # استخراج ساب‌دامین‌ها با رگکس
        results = re.findall(r'<li>(\w.*)</li>', response.text)
        results = [f"{result.strip()}.{domain}" for result in results]

        print(f"{colors.Gray}done for {domain}, results: {len(results)}{colors.Reset}")
        return results

    except requests.exceptions.Timeout:
        print(f"[{current_time()}] [!] Timeout exceeded for {domain} on AbuseIPDB. Skipping...")
        return []
    except requests.exceptions.RequestException as e:
        print(f"[{current_time()}] [!] Network error occurred for {domain}: {e}")
        return []

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"[{current_time()}] Usage: watch_abuseipdb domain")
        sys.exit(1)

    domain = sys.argv[1]
    program = Programs.objects(scopes=domain).first()

    if program:
        print(f"[{current_time()}] running abuseipdb module for {domain}")
        subs = abuseipdb(domain)

        for sub in subs:
            if re.search(r'\.\s*' + re.escape(domain), sub, re.IGNORECASE):
                upsert_subdomain(program.program_name, sub, "abuseipdb") 
    else:
        print(f"[{current_time()}] scope for {domain} does not exist in watchtower")