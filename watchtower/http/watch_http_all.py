#!/usr/bin/env python3
import sys
import os
import json
import tempfile
import argparse
import shutil

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import Programs, LiveSubdomains, upsert_http, current_time
from utils.safe_subprocess import run_command_safe
from utils.notify import flush_all
from utils.cli_helpers import parse_program_filter

def get_httpx_path():
    if "HTTPX_PATH" in os.environ:
        return os.environ["HTTPX_PATH"]
    if shutil.which("httpx"):
        return shutil.which("httpx")
    fallback_path = os.path.expanduser("~/go/bin/httpx")
    if os.path.exists(fallback_path):
        return fallback_path
    return "httpx"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Httpx All for all (or one/multiple) program(s).")
    parser.add_argument('--program', type=str, default=None,
                        help="Run only for the specified program name(s), comma-separated.")
    args = parser.parse_args()

    program_filter = parse_program_filter(args.program)

    if program_filter:
        print(f"[{current_time()}] Running in filtered mode for programs: {', '.join(program_filter)}")
        programs = Programs.objects(program_name__in=program_filter)
        
        found_programs = [p.program_name for p in programs]
        for p in program_filter:
            if p not in found_programs:
                print(f"[{current_time()}] [!] Warning: program '{p}' not found in database, skipping")
                
        if not programs:
            print(f"[{current_time()}] [!] Error: None of the specified programs were found in database.")
            sys.exit(1)
    else:
        print(f"[{current_time()}] Running in full mode (all programs)")
        programs = Programs.objects.all()
    
    for program in programs:
        distinct_scopes = LiveSubdomains.objects(program_name=program.program_name).distinct('scope')
        
        if not distinct_scopes:
            print(f"[{current_time()}] No live subdomains found in DB for program: {program.program_name}")
            continue

        for scope in distinct_scopes:
            live_subs = LiveSubdomains.objects(scope=scope, program_name=program.program_name)
            if live_subs:
                print(f"[{current_time()}] Running Httpx All module for scope: {scope}")
                
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
                    for live in live_subs:
                        temp_file.write(f"{live.subdomain}\n")
                    temp_file_path = temp_file.name

                    command = [
                        get_httpx_path(), 
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

                results = run_command_safe(command, timeout=300)

                # 1. مدیریت Silent Failure
                if results is None:
                    print(f"[{current_time()}] [!] Httpx failed or timed out for scope: {scope}")
                elif results:
                    for line in results:
                        if not line.strip(): continue
                        try:
                            json_obj = json.loads(line.strip())
                            
                            # 3. حل مشکل استرینگ خالی 
                            subdomain_name = json_obj.get('input') or json_obj.get('vhost') or json_obj.get('url', '').replace('https://', '').replace('http://', '').strip('/')
                            
                            if not subdomain_name:
                                print(f"[{current_time()}] [!] Warning: Could not extract subdomain from httpx output")
                                continue
                                
                            # 2. بررسی موفقیت‌آمیز بودن اینسرت
                            success = upsert_http({
                                "subdomain": subdomain_name,
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
                            if not success:
                                print(f"[{current_time()}] [!] Failed to upsert HTTP record for {subdomain_name}")
                        except Exception as e:
                            # 4. جلوگیری از قطع شدن حلقه در صورت کرش‌های غیرمنتظره
                            print(f"[{current_time()}] [!] Error processing httpx result for {subdomain_name if 'subdomain_name' in locals() else 'unknown'}: {e}")
                
                try:
                    os.unlink(temp_file_path)
                except:
                    pass

    flush_all()