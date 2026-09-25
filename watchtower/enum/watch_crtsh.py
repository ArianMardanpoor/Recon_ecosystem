#!/usr/bin/env python3
import sys, os, psycopg2, re, requests, json

# اضافه کردن مسیرها برای دسترسی به دیتابیس
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import Programs, bulk_upsert_subdomains, current_time

class colors:
    Gray = "\033[90m"
    Reset = "\033[0m"

def crtsh_psql(domain):
    """تلاش برای دریافت ساب‌دامین‌ها از دیتابیس مستقیم crt.sh"""
    db_params = {
        'dbname': 'certwatch',
        'user': 'guest',
        'password': '',
        'host': 'crt.sh',
        'port': 5432,
        'connect_timeout': 10
    }
    query = "SELECT ci.NAME_VALUE FROM certificate_and_identities ci WHERE plainto_tsquery('certwatch', %s) @@ identities(ci.CERTIFICATE)"
    
    processed_results = set()
    try:
        connection = psycopg2.connect(**db_params)
        connection.autocommit = True
        cursor = connection.cursor()
        cursor.execute("SET statement_timeout = 20000;")
        cursor.execute(query, (domain,))
        results = cursor.fetchall()
        
        for row in results:
            name_value = row[0].strip().lower()
            if domain in name_value and '*' not in name_value:
                for sub in name_value.split('\n'):
                    if sub.endswith(domain):
                        processed_results.add(sub)
        return list(processed_results)
    except Exception as e:
        print(f"[{current_time()}] PSQL connection to crt.sh failed: {e}")
        return None
    finally:
        if 'connection' in locals() and connection:
            cursor.close()
            connection.close()

def crtsh_api(domain):
    """Fallback: استفاده از API JSON سایت crt.sh"""
    print(f"{colors.Gray}[{current_time()}] Falling back to crt.sh JSON API for {domain}...{colors.Reset}")
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            data = response.json()
            subs = set()
            for entry in data:
                name_value = entry['name_value'].lower()
                for sub in name_value.split('\n'):
                    if sub.endswith(domain) and '*' not in sub:
                        subs.add(sub)
            return list(subs)
    except Exception as e:
        print(f"[{current_time()}] crt.sh API error: {e}")
    return []

def crtsh(domain):
    print(f"{colors.Gray}[{current_time()}] Querying crt.sh for {domain}...{colors.Reset}")
    # ابتدا تلاش برای PSQL
    results = crtsh_psql(domain)
    # اگر PSQL شکست خورد یا خالی بود، تلاش برای API
    if results is None or len(results) == 0:
        results = crtsh_api(domain)
    return results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"[{current_time()}] Usage: python3 watch_crtsh.py <domain>")
        sys.exit(1)
        
    domain = sys.argv[1]
    program = Programs.objects(scopes__in=[domain]).first()

    if program:
        print(f"[{current_time()}] Running Crtsh module for {domain}")
        subs = crtsh(domain)
        print(f"{colors.Gray}[{current_time()}] Crtsh found {len(subs)} subdomains for {domain}{colors.Reset}")
        
        if subs:
            bulk_upsert_subdomains(program.program_name, subs, "crtsh")
    else:
        print(f"[{current_time()}] Scope for {domain} does not exist in watchtower")
