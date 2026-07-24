#!/usr/bin/env python3
import sys, os, subprocess
import argparse
from concurrent.futures import ThreadPoolExecutor

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import Programs, current_time
from utils.scope_classifier import is_enumerable_domain
from utils.cli_helpers import parse_program_filter

ENUM_DIR = os.path.dirname(os.path.abspath(__file__))

def run_module(command):
    try:
        print(f"[{current_time()}] Starting: {' '.join(command)}")
        result = subprocess.run(command, capture_output=True, text=True, timeout=600)
        if result.returncode != 0:
            print(f"[{current_time()}] Error in {' '.join(command)}:\n{result.stderr}")
    except subprocess.TimeoutExpired:
        print(f"[{current_time()}] [!] Timeout for: {' '.join(command)}")
    except Exception as e:
        print(f"[{current_time()}] Exception: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run enum modules for all (or one/multiple) program(s).")
    parser.add_argument('--program', type=str, default=None,
                        help="Run enum only for the specified program name(s), comma-separated.")
    args = parser.parse_args()

    program_filter = parse_program_filter(args.program)

    # ۱. واکشی اطلاعات از دیتابیس[cite: 6]
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

    commands_to_run = []

    for p in programs:
        skipped_count = 0
        program_name = getattr(p, "program_name", "Unknown")
        
        for scope in p.scopes:
            if not is_enumerable_domain(scope):
                skipped_count += 1
                continue
                
            modules = [
                "watch_subfinder.py",
                "watch_crtsh.py",
                "watch_waybackurls.py",
            ]
            
            for mod in modules:
                commands_to_run.append(["python3", os.path.join(ENUM_DIR, mod), scope])
                
        if skipped_count > 0:
            print(f"[{current_time()}] Skipped {skipped_count} non-enumerable scopes (URLs/IPs) for program '{program_name}'.")

    print(f"[{current_time()}] Starting {len(commands_to_run)} enumeration tasks...")
    
    max_workers = int(os.environ.get("ENUM_MAX_WORKERS", 10))
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(run_module, commands_to_run)
        
    print(f"[{current_time()}] All enumeration modules finished. Starting DNS Resolution...")
    print(f"[{current_time()}] Watchtower Recon Cycle Completed!")