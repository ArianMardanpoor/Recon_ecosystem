#!/usr/bin/env python3
import sys
import os
import json
import tempfile

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import LiveSubdomains, upsert_http, current_time
from utils.safe_subprocess import run_command_safe

class colors:
    Gray = "\033[90m"
    Reset = "\033[0m"

def run_httpx_bulk(subdomains, domain):
    if not subdomains:
        print(f"[{current_time()}] No live subdomains to scan for {domain}")
        return
    
    # نوشتن گروهی ساب‌دامین‌ها در فایل موقت جهت افزایش سرعت بیست برابری
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
        for sub in subdomains:
            temp_file.write(f"{sub}\n")
        temp_file_path = temp_file.name

    command = [
        "httpx",
        "-l", temp_file_path,
        "-silent",
        "-json",
        "-favicon",
        "-tech-detect",
        "-status-code",
        "-title",
        "-threads", "30",
        "-timeout", "5",
        "-retries", "1"
    ]
    
    print(f"{colors.Gray}[{current_time()}] Executing httpx bulk for {len(subdomains)} subdomains...{colors.Reset}")
    results = run_command_safe(command)
    
    if results:
        for line in results:
            if not line.strip(): continue
            try:
                json_obj = json.loads(line.strip())
                # استخراج ساب‌دامین اصلی از ورودی httpx
                subdomain_name = json_obj.get('input', json_obj.get('vhost', ''))
                
                upsert_http({
                    "subdomain": subdomain_name,
                    "scope": domain,
                    "ips": json_obj.get('a', []),
                    "tech": json_obj.get('tech', []),
                    "title": json_obj.get('title', ''),
                    "status_code": json_obj.get('status_code', 0),
                    "headers": json_obj.get('headers', {}),
                    "url": json_obj.get('url', ''),
                    "final_url": json_obj.get('final_url', ''),
                    "favicon": json_obj.get('favicon', ''),
                })
            except json.JSONDecodeError as e:
                print(f"[{current_time()}] JSON decode error: {e}")

    try:
        os.unlink(temp_file_path)
    except:
        pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"[{current_time()}] Usage: python3 watch_http.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1]
    live_subdomains = LiveSubdomains.objects(scope=domain)
    
    if live_subdomains:
        subdomain_list = [live.subdomain for live in live_subdomains]
        run_httpx_bulk(subdomain_list, domain)
    else:
        print(f"[{current_time()}] No live subdomains found for scope: {domain}")