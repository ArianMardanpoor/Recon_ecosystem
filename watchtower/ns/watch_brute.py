# all code like watch_ns.py but with ShuffleDns instead of dnsx#!/usr/bin/env python3
import sys
import os
import tempfile

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import Programs, bulk_upsert_subdomains, current_time
from utils.safe_subprocess import run_command_safe


WORDLIST = "~/wordlists/subdomains.txt" 
RESOLVERS = "/etc/resolvers.txt"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"[{current_time()}] Usage: python3 watch_brute.py <domain>")
        sys.exit(1)
        
    domain = sys.argv[1]
    program = Programs.objects(scopes__in=[domain]).first()
    
    if program:
        print(f"[{current_time()}] Starting Brute-force with Shuffledns for {domain}")
        
        if not os.path.exists(WORDLIST) or not os.path.exists(RESOLVERS):
            print(f"[{current_time()}] Error: Wordlist or Resolvers file missing! Please check paths.")
            sys.exit(1)

        command = [
            "shuffledns",
            "-d", domain,
            "-w", WORDLIST,
            "-r", RESOLVERS,
            "-silent"
        ]
        
        results = run_command_safe(command)
        if results:
            discovered_subs = [line.strip() for line in results if line.strip()]
            print(f"[{current_time()}] Shuffledns found {len(discovered_subs)} subdomains.")
            # ثبت مستقیم و گروهی نتایج در دیتابیس
            bulk_upsert_subdomains(program.program_name, discovered_subs, "shuffledns")
    else:
        print(f"[{current_time()}] Scope for {domain} does not exist in watchtower.")