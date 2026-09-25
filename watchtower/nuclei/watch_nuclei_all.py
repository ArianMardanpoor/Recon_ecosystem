#!/usr/bin/env python3
import sys
import os
import tempfile

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import Http, current_time
from utils.safe_subprocess import run_command_safe

if __name__ == "__main__":
    http_objs = Http.objects.all()

    if http_objs:
        print(f"[{current_time()}] Running Nuclei All module for all targets")
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
            for http_obj in http_objs:
                if http_obj.url:
                    temp_file.write(f"{http_obj.url}\n")
            temp_file_path = temp_file.name

        config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "public-config.yaml"))
        command = ["nuclei", "-l", temp_file_path, "-silent"]
        
        if os.path.exists(config_path):
            command.extend(["-config", config_path])

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
        print(f"[{current_time()}] No HTTP services found in database to scan.")