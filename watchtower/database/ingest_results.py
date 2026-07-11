#!/usr/bin/env python3
import sys
import os
import re
import json
from datetime import datetime

# Import DB functions as requested. (Assumes these exist in db.py)
from db import upsert_scan_artifacts, upsert_scan_findings

def current_time():
    """Returns formatted current time for logging."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def get_safe_name(text):
    """Replaces non-alphanumeric characters with underscores (matching Go pipeline)."""
    return re.sub(r'[^a-zA-Z0-9]', '_', text)

def read_unique_lines(filepath):
    """Reads a file, strips whitespace, dedupes lines, and silently skips if missing."""
    if not os.path.isfile(filepath):
        return []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return list(set(line.strip() for line in f if line.strip()))
    except Exception as e:
        print(f"[{current_time()}] [خطا] مشکل در خواندن فایل {filepath}: {e}")
        return []

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 ingest_results.py <hostname>")
        sys.exit(1) # Exit non-zero only if the argument is missing

    hostname = sys.argv[1]
    safe_name = get_safe_name(hostname)

    # File paths based on pipeline structure
    passive_path = f"results/passive/{hostname}.passive"
    katana_path = f"results/katana/{safe_name}-katana.txt"
    params_path = f"results/params/{hostname}-param.txt"
    findings_path = "results/raw_findings.jsonl"

    # 3. Read files, dedupe, and strip
    passive_urls = read_unique_lines(passive_path)
    crawled_urls = read_unique_lines(katana_path)
    discovered_params = read_unique_lines(params_path)

    # 4. Call upsert_scan_artifacts
    try:
        upsert_scan_artifacts(
            hostname=hostname,
            passive_urls=passive_urls,
            crawled_urls=crawled_urls,
            discovered_params=discovered_params
        )
    except Exception as e:
        print(f"[{current_time()}] [خطا] مشکل در ثبت آرتیفکت‌ها در دیتابیس برای {hostname}: {e}")

    # 5. Parse and filter raw_findings.jsonl
    findings_list = []
    if os.path.isfile(findings_path):
        try:
            with open(findings_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        root_domain = obj.get('root_domain', '')
                        url = obj.get('url', '')
                        
                        # Filter entries relevant to this hostname
                        if hostname in root_domain or hostname in url:
                            findings_list.append(obj)
                    except json.JSONDecodeError:
                        pass # Silently skip malformed JSON lines
        except Exception as e:
            print(f"[{current_time()}] [خطا] مشکل در پردازش فایل یافته‌ها {findings_path}: {e}")

    # Call upsert_scan_findings if there are any valid findings
    try:
        upsert_scan_findings(hostname=hostname, findings_list=findings_list)
    except Exception as e:
        print(f"[{current_time()}] [خطا] مشکل در ثبت یافته‌ها در دیتابیس برای {hostname}: {e}")

    # 6. One-line summary
    print(f"[{current_time()}] Summary for {hostname}: {len(passive_urls)} passive, {len(crawled_urls)} crawled, {len(discovered_params)} params, {len(findings_list)} findings ingested. final_scan_status: SUCCESS")

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        # Catch any unexpected global errors and log in Persian, exiting cleanly.
        print(f"[{current_time()}] [خطا] خطای پیش‌بینی نشده در اسکریپت Ingest: {e}")
        sys.exit(0)