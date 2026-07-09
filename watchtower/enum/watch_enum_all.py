#!/usr/bin/env python3
import sys, os, subprocess
from concurrent.futures import ThreadPoolExecutor

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import Programs, current_time

ENUM_DIR = os.path.dirname(os.path.abspath(__file__))

def run_module(command):
    try:
        print(f"[{current_time()}] Starting: {' '.join(command)}")
        # تایم‌اوت ۱۰ دقیقه‌ای برای ماژول‌های سنگین‌تر مثل GitHub یا Wayback
        result = subprocess.run(command, capture_output=True, text=True, timeout=600)
        if result.returncode != 0:
            print(f"[{current_time()}] Error in {' '.join(command)}:\n{result.stderr}")
    except subprocess.TimeoutExpired:
        print(f"[{current_time()}] [!] Timeout for: {' '.join(command)}")
    except Exception as e:
        print(f"[{current_time()}] Exception: {e}")

if __name__ == "__main__":
    programs = Programs.objects.all()
    commands_to_run = []

    for p in programs:
        for scope in p.scopes:
            # لیست ماژول‌های فعال
            modules = [
                "watch_subfinder.py",
                "watch_crtsh.py",
                "watch_waybackurls.py",
            ]
            
            for mod in modules:
                commands_to_run.append(["python3", os.path.join(ENUM_DIR, mod), scope])

    print(f"[{current_time()}] Starting {len(commands_to_run)} enumeration tasks...")
    
    # اجرای موازی ماژول‌ها
    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(run_module, commands_to_run)
        
    print(f"[{current_time()}] All enumeration modules finished. Starting DNS Resolution...")

    print(f"[{current_time()}] Watchtower Recon Cycle Completed!")
