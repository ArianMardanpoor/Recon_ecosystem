#!/usr/bin/env python3
import os
import sys
import argparse
from datetime import datetime

# Add parent directory to sys.path to import modules (watchtower/)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.db import Http, retry_on_autoreconnect, current_time
from utils.cli_helpers import parse_program_filter

class colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'

def parse_iso_date(date_str):
    """Safely parse an ISO date string."""
    try:
        # Handling the 'Z' suffix for UTC commonly found in Go/JS ISO strings
        return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
    except ValueError as e:
        print(f"{colors.RED}[!] Error parsing date '{date_str}': {e}{colors.ENDC}")
        sys.exit(1)

@retry_on_autoreconnect(max_retries=3)
def purge_stale_findings(program_filter, before_dt, dry_run):
    """Iterate through Http documents and purge matched stale xssniper findings."""
    query = {}
    if program_filter:
        query['program_name__in'] = program_filter

    # Retrieve Http documents matching the query parameters
    docs = Http.objects(**query)
    
    total_scanned = 0
    total_purged = 0
    total_changed_docs = 0

    for doc in docs:
        total_scanned += 1
        original_findings = doc.findings
        
        if not original_findings:
            continue

        new_findings = []
        purged_count = 0

        for finding in original_findings:
            is_xssniper = finding.get('discovery_source') == 'xssniper'
            is_high = str(finding.get('confidence', '')).upper() == 'HIGH'
            timestamp_str = finding.get('timestamp')
            
            is_stale = False
            if timestamp_str:
                try:
                    finding_dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    if finding_dt < before_dt:
                        is_stale = True
                except ValueError:
                    pass  # Keep findings with unparseable timestamps to be safe

            if is_xssniper and is_high and is_stale:
                purged_count += 1
            else:
                new_findings.append(finding)

        if purged_count > 0:
            total_purged += purged_count
            total_changed_docs += 1

            old_status = doc.scan_status
            calculated_status = "clean"
            
            if new_findings:
                calculated_status = "findings"
                # Check remaining findings to see if confirmed_vuln is still valid
                if any(str(f.get('confidence')).upper() == 'HIGH' for f in new_findings):
                    calculated_status = "confirmed_vuln"

            action = "Would update" if dry_run else "Updated"
            color = colors.YELLOW if dry_run else colors.GREEN

            print(f"[{current_time()}] {color}{action} {doc.subdomain}: Removed {purged_count} finding(s) | Status: {old_status} -> {calculated_status}{colors.ENDC}")

            if not dry_run:
                doc.findings = new_findings
                doc.scan_status = calculated_status
                doc.last_update = datetime.now()
                doc.save()

    return total_scanned, total_purged, total_changed_docs

def main():
    parser = argparse.ArgumentParser(description="Purge stale XSS false positives from Http findings.")
    parser.add_argument('--before', type=str, required=True,
                        help="ISO datetime string (e.g. 2023-10-27T10:00:00). Findings older than this time will be purged.")
    parser.add_argument('--program', type=str, default=None,
                        help="Filter to specific program name(s), comma-separated.")
    parser.add_argument('--dry-run', action='store_true',
                        help="Only print what would be modified without actually saving to DB.")
    
    args = parser.parse_args()
    program_filter = parse_program_filter(args.program)
    before_dt = parse_iso_date(args.before)
    
    print(f"[{current_time()}] {colors.GREEN}Starting stale findings purge task...{colors.ENDC}")
    print(f"[{current_time()}] {colors.GREEN}Target before date: {before_dt.isoformat()}{colors.ENDC}")
    
    if args.dry_run:
        print(f"[{current_time()}] {colors.YELLOW}[!] RUNNING IN DRY-RUN MODE - NO MODIFICATIONS WILL OCCUR{colors.ENDC}")
    if program_filter:
        print(f"[{current_time()}] {colors.GREEN}Filtering scope to programs: {', '.join(program_filter)}{colors.ENDC}")

    # Execute the cleanup logic
    scanned, purged, changed = purge_stale_findings(program_filter, before_dt, args.dry_run)

    # ==========================================
    # Final Summary
    # ==========================================
    print(f"\n[{current_time()}] {colors.GREEN}=== Purge Summary ==={colors.ENDC}")
    
    msg_color = colors.YELLOW if args.dry_run else colors.GREEN
    status_msg = "(DRY-RUN)" if args.dry_run else ""
    
    print(f"[{current_time()}] {msg_color}Total Docs Scanned: {scanned}{colors.ENDC}")
    print(f"[{current_time()}] {msg_color}Total Findings Purged: {purged} {status_msg}{colors.ENDC}")
    print(f"[{current_time()}] {msg_color}Total Docs Changed: {changed} {status_msg}{colors.ENDC}")

if __name__ == "__main__":
    main()