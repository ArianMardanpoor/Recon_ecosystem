#!/usr/bin/env python3
import sys
import os
import json
import tempfile

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import Programs, LiveSubdomains, upsert_http, current_time
from utils.safe_subprocess import run_command_safe
from utils.notify import flush_all

if __name__ == "__main__":
    programs = Programs.objects.all()
    
    for program in programs:
        for scope in program.scopes:
            live_subs = LiveSubdomains.objects(scope=scope)
            if live_subs:
                print(f"[{current_time()}] Running Httpx All module for scope: {scope}")
                
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
                    for live in live_subs:
                        temp_file.write(f"{live.subdomain}\n")
                    temp_file_path = temp_file.name

                command = [
                    "httpx", 
                    "-l", temp_file.name, 
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

                results = run_command_safe(command, timeout=300)

                if results:
                    for line in results:
                        if not line.strip(): continue
                        try:
                            json_obj = json.loads(line.strip())
                            upsert_http({
                                "subdomain": json_obj.get('input', ''),
                                "scope": scope,
                                "ips": json_obj.get('a', []),
                                "tech": json_obj.get('tech', []),
                                "title": json_obj.get('title', ''),
                                "status_code": json_obj.get('status_code', 0),
                                "headers": json_obj.get('headers', {}),
                                "url": json_obj.get('url', ''),
                                "final_url": json_obj.get('final_url', ''),
                                "favicon": json_obj.get('favicon', ''),
                            })
                        except Exception as e:
                            print(f"[{current_time()}] Error parsing httpx line: {e}")
                
                try:
                    os.unlink(temp_file_path)
                except:
                    pass
            else:
                print(f"[{current_time()}] No live subdomains for scope: {scope}")

    # ارسال تمام نوتیف‌های بافرشده در پایان اسکن
    flush_all()