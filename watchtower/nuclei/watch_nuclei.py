#!/usr/bin/env python3
import sys
import os
import tempfile

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import Http, current_time
from utils.safe_subprocess import run_command_safe

class colors:
    Gray = "\033[90m"
    Reset = "\033[0m"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"[{current_time()}] Usage: python3 watch_nuclei.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1]
    http_services = Http.objects(scope=domain)

    if http_services:
        print(f"[{current_time()}] Running Nuclei module for {domain}")
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
            for service in http_services:
                if service.url:
                    temp_file.write(f"{service.url}\n")
            temp_file_path = temp_file.name

        config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "public-config.yaml"))
        
        # ساخت دستور برای اجرای امن
        command = ["nuclei", "-l", temp_file_path, "-silent"]
        if os.path.exists(config_path):
            command.extend(["-config", config_path])

        print(f"{colors.Gray}[{current_time()}] Executing Nuclei bulk scan...{colors.Reset}")
        results = run_command_safe(command)
        
        if results:
            for line in results:
                if line.strip():
                    print(f"[{current_time()}] [VULN FOUND] {line.strip()}")
        
        try:
            os.unlink(temp_file_path)
        except:
            pass
    else:
        print(f"[{current_time()}] No HTTP services found for scope: {domain}")