#!/usr/bin/env python3
import sys
import os
import json
import tempfile

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import Subdomains, upsert_live, current_time
from utils.safe_subprocess import run_command_safe

class colors:
    Gray = "\033[90m"
    Reset = "\033[0m"

def dnsx(subdomain_list, domain):
    if not subdomain_list:
        print(f"[{current_time()}] No subdomains to check for {domain}")
        return True
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
        for sub in subdomain_list:
            temp_file.write(f"{sub}\n")
        temp_file_path = temp_file.name
    
    try:
        command = [
            "dnsx", "-l", temp_file_path, "-silent", "-resp", "-json",
            "-r", "8.8.8.8,1.1.1.1", "-t", "50", "-rl", "100"
        ]
        
        print(f"{colors.Gray}[{current_time()}] Executing dnsx for {domain}{colors.Reset}")
        result = run_command_safe(command)
        
        if result:
            for line in result:
                if not line.strip(): continue
                try:
                    obj = json.loads(line.strip())
                    upsert_live({
                        'subdomain': obj.get('host', ''),
                        'scope': domain,
                        'ips': obj.get('a', []),
                        'cdn': ''  # در آینده ماژول CDN چک اضافه می‌شود
                    })
                except json.JSONDecodeError:
                    continue
        print(f"[{current_time()}] dnsx completed for {domain}")
    finally:
        try:
            os.unlink(temp_file_path)
        except:
            pass
    return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"[{current_time()}] Usage: watch_ns.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1]
    subdomains = Subdomains.objects(scope=domain)
    
    if subdomains:
        print(f"[{current_time()}] Running dnsx module for {domain}")
        subdomain_list = [s.subdomain for s in subdomains]
        dnsx(subdomain_list, domain)
    else:
        print(f"[{current_time()}] No subdomains found for scope: {domain}")