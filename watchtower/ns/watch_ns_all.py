#!/usr/bin/env python3
import sys
import os
import json
import tempfile

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import Programs, Subdomains, upsert_live, current_time
from utils.safe_subprocess import run_command_safe

if __name__ == "__main__":
    programs = Programs.objects.all()
    
    for program in programs:
        for scope in program.scopes:
            subdomains = Subdomains.objects(scope=scope)
            if subdomains:
                print(f"[{current_time()}] Running Dnsx All for scope: {scope}")
                
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
                    for sub in subdomains:
                        temp_file.write(f"{sub.subdomain}\n")
                    temp_file_path = temp_file.name

                command = [
                    "dnsx", "-l", temp_file_path, "-silent", "-resp", "-json",
                    "-r", "8.8.8.8,1.1.1.1", "-t", "50", "-rl", "100"
                ]

                results = run_command_safe(command)
                if results:
                    for line in results:
                        if not line.strip(): continue
                        try:
                            obj = json.loads(line.strip())
                            upsert_live({
                                'subdomain': obj.get('host', ''),
                                'scope': scope,
                                'ips': obj.get('a', []),
                                'cdn': ''
                            })
                        except Exception as e:
                            print(f"[{current_time()}] Error parsing dnsx line: {e}")

                try:
                    os.unlink(temp_file_path)
                except:
                    pass
            else:
                print(f"[{current_time()}] No subdomains found in DB for scope: {scope}")