#!/usr/bin/env python3
import sys, os, subprocess

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import Programs, bulk_upsert_subdomains, current_time

class colors:
    Gray = "\033[90m"
    Reset = "\033[0m"

def run_assetfinder(domain):
    """اجرای Assetfinder برای کشف دارایی‌های مرتبط"""
    command = ["assetfinder", "--subs-only", domain]
    
    print(f"{colors.Gray}[{current_time()}] Executing: {' '.join(command)}{colors.Reset}")
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=180)
        if result.returncode != 0:
            print(f"[{current_time()}] Assetfinder failed for {domain}: {result.stderr}")
            return []
        
        subs = [line.strip() for line in result.stdout.splitlines() if line.strip() and line.endswith(domain)]
        return subs
    except subprocess.TimeoutExpired:
        print(f"[{current_time()}] Assetfinder timed out for {domain}.")
        return []
    except Exception as e:
        print(f"[{current_time()}] Exception running Assetfinder: {e}")
        return []

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"[{current_time()}] Usage: python3 watch_assetfinder.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1]
    program = Programs.objects(scopes__in=[domain]).first()
    
    if program:
        print(f"[{current_time()}] Running Assetfinder module for {domain}")
        subs = run_assetfinder(domain)
        print(f"{colors.Gray}[{current_time()}] Assetfinder found {len(subs)} subdomains for {domain}{colors.Reset}")
        if subs:
            bulk_upsert_subdomains(program.program_name, subs, "assetfinder")
