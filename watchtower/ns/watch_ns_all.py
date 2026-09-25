#!/usr/bin/env python3
import sys
import os
import json
import tempfile
import argparse

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import Programs, Subdomains, upsert_live, current_time
from utils.safe_subprocess import run_command_safe
from utils.wildcard_filter import filter_wildcards
from utils.cli_helpers import parse_program_filter

DNSX_BASE_FLAGS = ["-silent", "-resp", "-json", "-r", "8.8.8.8,1.1.1.1", "-t", "50", "-rl", "100"]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Dnsx All for all (or one/multiple) program(s).")
    parser.add_argument('--program', type=str, default=None,
                        help="Run only for the specified program name(s), comma-separated.")
    args = parser.parse_args()

    program_filter = parse_program_filter(args.program)

    # ۱. واکشی اطلاعات از دیتابیس
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
        # استخراج اسکوپ‌های واقعی این برنامه از کالکشن Subdomains
        distinct_scopes = Subdomains.objects(program_name=program.program_name).distinct('scope')
        
        if not distinct_scopes:
            print(f"[{current_time()}] No subdomains found in DB for program: {program.program_name}")
            continue

        for scope in distinct_scopes:
            # فیلتر هم‌زمان روی scope و program_name برای جلوگیری از تداخل
            subdomains = Subdomains.objects(scope=scope, program_name=program.program_name)
            if subdomains:
                print(f"[{current_time()}] Running Dnsx All for scope: {scope}")
                
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
                    for sub in subdomains:
                        temp_file.write(f"{sub.subdomain}\n")
                    temp_file_path = temp_file.name

                command = ["dnsx", "-l", temp_file_path] + DNSX_BASE_FLAGS

                live_map = {}
                results = run_command_safe(command)
                if results:
                    for line in results:
                        if not line.strip():
                            continue
                        try:
                            obj = json.loads(line.strip())
                            host = obj.get('host', '')
                            ips = obj.get('a', [])
                            if host:
                                live_map[host] = ips
                        except Exception as e:
                            print(f"[{current_time()}] Error parsing dnsx line: {e}")

                try:
                    os.unlink(temp_file_path)
                except:
                    pass

                if not live_map:
                    print(f"[{current_time()}] {scope}: 0 live")
                    continue

                genuine_map, discarded = filter_wildcards(live_map)

                for host, ips in genuine_map.items():
                    upsert_live({
                        'subdomain': host,
                        'scope': scope,
                        'ips': ips,
                        'cdn': ''
                    })

                print(f"[{current_time()}] {scope}: {len(genuine_map)} genuine live, "
                      f"{discarded} discarded (wildcard noise)")