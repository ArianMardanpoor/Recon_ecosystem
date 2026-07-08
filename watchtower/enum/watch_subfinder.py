#!/usr/bin/env python3
import sys
import os
import re

# اضافه کردن مسیرها
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "database")))

from database.db import Programs, upsert_subdomain, current_time
from utils.safe_subprocess import run_command_safe

class colors:
    Gray = "\033[90m"
    Reset = "\033[0m"


def subfinder(domain):
    """اجرای امن subfinder با استفاده از لیست آرگومان‌ها"""
    command = ["subfinder", "-d", domain, "-all", "-silent"]
    
    print(f"{colors.Gray}[{current_time()}] Executing: subfinder -d {domain} -all{colors.Reset}")
    
    results = run_command_safe(command)
    
    if results is None:
        print(f"[{current_time()}] Subfinder failed for {domain}")
        return []
    
    res_num = len(results)
    print(f"{colors.Gray}[{current_time()}] Subfinder done for {domain}, results: {res_num}{colors.Reset}")
    
    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"[{current_time()}] Usage: watch_subfinder.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1]
    
    # اعتبارسنجی دامنه
    if not domain or len(domain) > 253:
        print(f"[{current_time()}] Invalid domain: {domain}")
        sys.exit(1)
    
    # پیدا کردن برنامه بر اساس scope
    program = Programs.objects(scopes__in=[domain]).first()
    
    if not program:
        # سعی می‌کنیم دامنه اصلی را پیدا کنیم
        for prog in Programs.objects.all():
            for scope in prog.scopes:
                if domain.endswith(scope) or scope.endswith(domain):
                    program = prog
                    break
            if program:
                break
    
    if program:
        print(f"[{current_time()}] Running Subfinder module for {domain} (program: {program.program_name})")
        subs = subfinder(domain)
        
        for sub in subs:
            if sub and sub.strip():
                upsert_subdomain(program.program_name, sub.strip(), "subfinder")
    else:
        print(f"[{current_time()}] No program found for scope: {domain}")