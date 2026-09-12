#!/usr/bin/env python3
import sys
import os
import argparse
import tempfile
import shutil
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import LiveSubdomains, bulk_update_cdn_status, current_time
from utils.safe_subprocess import run_command_safe
from utils.cli_helpers import parse_program_filter

class colors:
    Gray = "\033[90m"
    Green = "\033[92m"
    Reset = "\033[0m"

def main():
    parser = argparse.ArgumentParser(description="Check CDN status of IPs using cut-cdn")
    parser.add_argument("--program", help="Comma-separated list of programs to filter")
    args = parser.parse_args()

    if not shutil.which("cut-cdn"):
        print(f"[{current_time()}] Error: cut-cdn binary not found in PATH. Exiting.", file=sys.stderr)
        sys.exit(1)

    programs = parse_program_filter(args.program)
    
    if programs:
        print(f"{colors.Gray}[{current_time()}] Running in filtered mode for programs: {', '.join(programs)}{colors.Reset}")
        query = LiveSubdomains.objects(program_name__in=programs, ips__not__size=0)
    else:
        print(f"{colors.Gray}[{current_time()}] Running in full mode (all programs){colors.Reset}")
        query = LiveSubdomains.objects(ips__not__size=0)

    # Flatten and extract unique IPs
    all_ips = set()
    for doc in query.only('ips'):
        for ip in doc.ips:
            if ip:
                all_ips.add(ip)

    if not all_ips:
        print(f"[{current_time()}] No IPs found to check.")
        sys.exit(0)

    temp_in = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
    temp_out = tempfile.NamedTemporaryFile(mode='r', delete=False, suffix='.txt')
    
    try:
        for ip in all_ips:
            temp_in.write(f"{ip}\n")
        temp_in.close()
        temp_out.close()

        cmd = ["cut-cdn", "-i", temp_in.name, "-o", temp_out.name]
        print(f"{colors.Gray}[{current_time()}] Executing cut-cdn on {len(all_ips)} distinct IPs...{colors.Reset}")
        run_command_safe(cmd)

        non_cdn_ips = set()
        if os.path.exists(temp_out.name):
            with open(temp_out.name, 'r') as f:
                for line in f:
                    ip = line.strip()
                    if ip:
                        non_cdn_ips.add(ip)

        cdn_ips = all_ips - non_cdn_ips

        ip_map = {}
        for ip in non_cdn_ips:
            ip_map[ip] = False
        for ip in cdn_ips:
            ip_map[ip] = True

        affected_docs_count = LiveSubdomains.objects(ips__in=list(all_ips)).count()
        
        bulk_update_cdn_status(ip_map)

        print(f"{colors.Green}[{current_time()}] cut-cdn: {len(all_ips)} IPs checked, {len(non_cdn_ips)} non-CDN, {len(cdn_ips)} CDN, {affected_docs_count} subdomains updated{colors.Reset}")

    finally:
        for tmp_file in [temp_in.name, temp_out.name]:
            try:
                if os.path.exists(tmp_file):
                    os.unlink(tmp_file)
            except Exception:
                pass

if __name__ == "__main__":
    main()