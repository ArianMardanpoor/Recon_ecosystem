#!/usr/bin/env python3
import os
import sys
import argparse

# Add parent directory to sys.path to import modules (watchtower/)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.db import Programs, Subdomains, LiveSubdomains, Http, retry_on_autoreconnect, current_time
from utils.cli_helpers import parse_program_filter

class colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'

# ==========================================
# Efficient Data Loading Functions
# ==========================================

@retry_on_autoreconnect(max_retries=3)
def get_valid_programs():
    """Retrieve all current, valid program_names from Programs collection."""
    return set(Programs.objects().distinct('program_name'))

@retry_on_autoreconnect(max_retries=3)
def get_valid_subdomains(program_filter=None):
    """Retrieve all valid subdomains currently residing in Subdomains collection."""
    if program_filter:
        return set(Subdomains.objects(program_name__in=program_filter).distinct('subdomain'))
    return set(Subdomains.objects().distinct('subdomain'))

@retry_on_autoreconnect(max_retries=3)
def get_collection_subdomains(collection_class, program_filter=None):
    if program_filter:
        return set(collection_class.objects(program_name__in=program_filter).distinct('subdomain'))
    return set(collection_class.objects().distinct('subdomain'))

@retry_on_autoreconnect(max_retries=3)
def get_collection_programs(collection_class, program_filter=None):
    if program_filter:
        return set(collection_class.objects(program_name__in=program_filter).distinct('program_name'))
    return set(collection_class.objects().distinct('program_name'))

# ==========================================
# Cleanup Action Handlers
# ==========================================

@retry_on_autoreconnect(max_retries=3)
def clean_by_subdomains(collection_class, subdomains_to_delete, program_filter, dry_run):
    if not subdomains_to_delete:
        return 0, []
    
    subs_list = list(subdomains_to_delete)
    query = {'subdomain__in': subs_list}
    if program_filter:
        query['program_name__in'] = program_filter
        
    qs = collection_class.objects(**query)
    count = qs.count()
    
    # Extract up to 10 samples
    sample_docs = qs.only('subdomain').limit(10)
    samples = [doc.subdomain for doc in sample_docs]
    
    if count > 0 and not dry_run:
        qs.delete()
        
    return count, samples

@retry_on_autoreconnect(max_retries=3)
def clean_by_programs(collection_class, programs_to_delete, program_filter, dry_run):
    if not programs_to_delete:
        return 0, []
        
    # If filtered, we only care about stale programs within our filter target
    if program_filter:
        programs_to_delete = programs_to_delete.intersection(set(program_filter))
        
    if not programs_to_delete:
        return 0, []
        
    progs_list = list(programs_to_delete)
    query = {'program_name__in': progs_list}
    
    qs = collection_class.objects(**query)
    count = qs.count()
    
    sample_docs = qs.only('subdomain').limit(10)
    samples = [doc.subdomain for doc in sample_docs]
    
    if count > 0 and not dry_run:
        qs.delete()
        
    return count, samples

# ==========================================
# Main Execution Flow
# ==========================================

def main():
    parser = argparse.ArgumentParser(description="Clean up orphaned LiveSubdomains and Http records.")
    parser.add_argument('--skip-orphan-subdomain-check', action='store_true', 
                        help="Skip checking for orphaned subdomains (no parent in Subdomains).")
    parser.add_argument('--skip-stale-program-check', action='store_true', 
                        help="Skip checking for stale programs (program_name missing from Programs).")
    parser.add_argument('--dry-run', action='store_true', 
                        help="Only print what would be deleted without actually executing .delete().")
    parser.add_argument('--program', type=str, default=None, 
                        help="Filter to specific program name(s), comma-separated.")
    
    args = parser.parse_args()
    program_filter = parse_program_filter(args.program)
    
    print(f"[{current_time()}] {colors.GREEN}Starting orphan cleanup task...{colors.ENDC}")
    if args.dry_run:
        print(f"[{current_time()}] {colors.YELLOW}[!] RUNNING IN DRY-RUN MODE - NO DELETIONS WILL OCCUR{colors.ENDC}")
    if program_filter:
        print(f"[{current_time()}] {colors.GREEN}Filtering scope to programs: {', '.join(program_filter)}{colors.ENDC}")
        
    stats = {
        'live_stale': 0,
        'http_stale': 0,
        'live_orphans': 0,
        'http_orphans': 0
    }

    # ==========================================
    # Check 1: Stale Programs
    # ==========================================
    if not args.skip_stale_program_check:
        print(f"\n[{current_time()}] {colors.GREEN}[+] Checking for Stale Programs...{colors.ENDC}")
        valid_programs = get_valid_programs()
        
        live_programs = get_collection_programs(LiveSubdomains, program_filter)
        http_programs = get_collection_programs(Http, program_filter)
        
        # Diff in-memory to find programs that exist in Live/Http but NOT in Programs collection
        stale_live = live_programs - valid_programs
        stale_http = http_programs - valid_programs
        
        if stale_live:
            count, samples = clean_by_programs(LiveSubdomains, stale_live, program_filter, args.dry_run)
            stats['live_stale'] = count
            action = "Would delete" if args.dry_run else "Deleted"
            color = colors.YELLOW if args.dry_run else colors.RED
            print(f"[{current_time()}] {color}{action} {count} LiveSubdomains linked to stale programs: {', '.join(stale_live)}{colors.ENDC}")
            if samples:
                print(f"    {colors.YELLOW}Samples: {', '.join(samples)}{colors.ENDC}")
                
        if stale_http:
            count, samples = clean_by_programs(Http, stale_http, program_filter, args.dry_run)
            stats['http_stale'] = count
            action = "Would delete" if args.dry_run else "Deleted"
            color = colors.YELLOW if args.dry_run else colors.RED
            print(f"[{current_time()}] {color}{action} {count} Http records linked to stale programs: {', '.join(stale_http)}{colors.ENDC}")
            if samples:
                print(f"    {colors.YELLOW}Samples: {', '.join(samples)}{colors.ENDC}")
                
        if not stale_live and not stale_http:
            print(f"[{current_time()}] {colors.GREEN}No stale programs found.{colors.ENDC}")
    else:
        print(f"\n[{current_time()}] {colors.YELLOW}[-] Skipping Stale Programs check (--skip-stale-program-check){colors.ENDC}")

    # ==========================================
    # Check 2: Orphan Subdomains
    # ==========================================
    if not args.skip_orphan_subdomain_check:
        print(f"\n[{current_time()}] {colors.GREEN}[+] Checking for Orphan Subdomains...{colors.ENDC}")
        valid_subdomains = get_valid_subdomains(program_filter)
        
        live_subdomains = get_collection_subdomains(LiveSubdomains, program_filter)
        http_subdomains = get_collection_subdomains(Http, program_filter)
        
        # Diff in-memory to find subdomains that exist in Live/Http but NOT in Subdomains collection
        orphans_live = live_subdomains - valid_subdomains
        orphans_http = http_subdomains - valid_subdomains
        
        if orphans_live:
            count, samples = clean_by_subdomains(LiveSubdomains, orphans_live, program_filter, args.dry_run)
            stats['live_orphans'] = count
            action = "Would delete" if args.dry_run else "Deleted"
            color = colors.YELLOW if args.dry_run else colors.RED
            print(f"[{current_time()}] {color}{action} {count} orphaned LiveSubdomains.{colors.ENDC}")
            if samples:
                print(f"    {colors.YELLOW}Samples: {', '.join(samples)}{colors.ENDC}")
                
        if orphans_http:
            count, samples = clean_by_subdomains(Http, orphans_http, program_filter, args.dry_run)
            stats['http_orphans'] = count
            action = "Would delete" if args.dry_run else "Deleted"
            color = colors.YELLOW if args.dry_run else colors.RED
            print(f"[{current_time()}] {color}{action} {count} orphaned Http records.{colors.ENDC}")
            if samples:
                print(f"    {colors.YELLOW}Samples: {', '.join(samples)}{colors.ENDC}")
                
        if not orphans_live and not orphans_http:
            print(f"[{current_time()}] {colors.GREEN}No orphaned subdomains found.{colors.ENDC}")
    else:
        print(f"\n[{current_time()}] {colors.YELLOW}[-] Skipping Orphan Subdomains check (--skip-orphan-subdomain-check){colors.ENDC}")

    # ==========================================
    # Final Summary
    # ==========================================
    print(f"\n[{current_time()}] {colors.GREEN}=== Cleanup Summary ==={colors.ENDC}")
    
    total_live = stats['live_stale'] + stats['live_orphans']
    total_http = stats['http_stale'] + stats['http_orphans']
    
    if total_live == 0 and total_http == 0:
        print(f"[{current_time()}] {colors.GREEN}Everything is clean! No orphans or stale records found.{colors.ENDC}")
    else:
        status_msg = "WOULD BE DELETED (DRY-RUN)" if args.dry_run else "SUCCESSFULLY DELETED"
        msg_color = colors.YELLOW if args.dry_run else colors.RED
        
        print(f"[{current_time()}] {msg_color}LiveSubdomains: {total_live} {status_msg}{colors.ENDC}")
        print(f"  - From stale programs: {stats['live_stale']}")
        print(f"  - Orphaned subdomains: {stats['live_orphans']}")
        
        print(f"[{current_time()}] {msg_color}Http records: {total_http} {status_msg}{colors.ENDC}")
        print(f"  - From stale programs: {stats['http_stale']}")
        print(f"  - Orphaned subdomains: {stats['http_orphans']}")

if __name__ == "__main__":
    main()