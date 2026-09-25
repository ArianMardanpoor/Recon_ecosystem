#!/usr/bin/env python3
import sys, os, subprocess

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import Programs, bulk_upsert_subdomains, current_time

class colors:
    Gray = "\033[90m"
    Reset = "\033[0m"

def run_amass(domain):
    """اجرای Amass در حالت Passive برای سرعت بیشتر و جلوگیری از شناسایی زودهنگام"""
    # -passive: فقط از منابع آنلاین استفاده می‌کند (بدون Brute-force یا Active DNS)
    # -d: تعیین دامنه هدف
    # -silent: فقط خروجی ساب‌دامین‌ها را نمایش می‌دهد
    command = ["amass", "enum", "-passive", "-d", domain, "-silent"]
    
    print(f"{colors.Gray}[{current_time()}] Executing: {' '.join(command)}{colors.Reset}")
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=1200)
        
        if result.returncode != 0:
            print(f"[{current_time()}] Amass failed for {domain}: {result.stderr}")
            return []
        
        subs = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return subs
        
    except subprocess.TimeoutExpired:
        print(f"[{current_time()}] Amass timed out for {domain}. Skipping...")
        return []
    except Exception as e:
        print(f"[{current_time()}] Exception running Amass: {e}")
        return []

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"[{current_time()}] Usage: python3 watch_amass.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1]
    
    # پیدا کردن برنامه بر اساس scope
    program = Programs.objects(scopes__in=[domain]).first()
    
    if program:
        print(f"[{current_time()}] Running Amass module for {domain}")
        subs = run_amass(domain)
        print(f"{colors.Gray}[{current_time()}] Amass found {len(subs)} subdomains for {domain}{colors.Reset}")
        
        if subs:
            # استفاده از متد bulk برای افزایش سرعت ثبت در دیتابیس
            bulk_upsert_subdomains(program.program_name, subs, "amass")
    else:
        print(f"[{current_time()}] No program found for scope: {domain}")
