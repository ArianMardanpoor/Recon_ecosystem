#!/usr/bin/env python3
import os
import sys
import json
import time
import logging
import argparse
from pathlib import Path
import requests
from requests.auth import HTTPBasicAuth

# ایمپورت کانفیگ از مسیر پروژه
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
try:
    import config
except ImportError:
    print("[-] Error: Could not import config.py. Make sure you are in the correct directory.")
    sys.exit(1)

# تنظیمات لاگر
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("H1_Sync")

# آدرس فایل هندل‌ها
HANDLES_FILE = Path(config.PROGRAMS_DIR) / 'h1_handles.txt'

def fetch_h1_scopes(handle, auth, max_retries=5):
    """
    Fetch structured scopes from HackerOne API with pagination and exponential backoff.
    دریافت اسکوپ‌ها از API با پشتیبانی از صفحه‌بندی و بک‌آف نمایی.
    """
    url = f"https://api.hackerone.com/v1/hackers/programs/{handle}/structured_scopes"
    headers = {"Accept": "application/json"}
    
    scopes = []
    outofscopes = []
    attempt = 0
    
    while url:
        try:
            response = requests.get(url, auth=auth, headers=headers, timeout=15)
            
            # Rate Limit Handling (429)
            if response.status_code == 429:
                attempt += 1
                if attempt > max_retries:
                    logger.error(f"[{handle}] Max retries reached for 429 Too Many Requests.")
                    break
                sleep_time = (2 ** attempt)
                logger.warning(f"[{handle}] Rate limited (429). Backing off for {sleep_time} seconds...")
                time.sleep(sleep_time)
                continue  # Retry same URL
            
            # Reset attempt on success
            attempt = 0
            
            # HTTP Errors Handling
            if response.status_code in [401, 403]:
                logger.error(f"[{handle}] Auth Error ({response.status_code}). Check your H1_API_USERNAME and H1_API_TOKEN.")
                return None, None
            elif response.status_code == 404:
                logger.error(f"[{handle}] Program not found (404). Check if the handle is correct.")
                return None, None
            elif response.status_code != 200:
                logger.error(f"[{handle}] Unexpected error: {response.status_code} - {response.text}")
                return None, None
            
            data = response.json()
            
            # Parse targets
            for item in data.get('data', []):
                attrs = item.get('attributes', {})
                asset_type = attrs.get('asset_type')
                asset_identifier = attrs.get('asset_identifier')
                eligible = attrs.get('eligible_for_submission', False)
                
                if asset_type in ['URL', 'WILDCARD'] and asset_identifier:
                    if eligible:
                        scopes.append(asset_identifier)
                    else:
                        outofscopes.append(asset_identifier)
            
            # Pagination check
            links = data.get('links', {})
            url = links.get('next')
            
        except requests.exceptions.RequestException as e:
            logger.error(f"[{handle}] Request failed: {e}")
            return None, None
            
    return list(set(scopes)), list(set(outofscopes))

def print_diff(handle, old_scopes, old_outofscopes, new_scopes, new_outofscopes):
    """Prints the difference between old and new scopes for manual review."""
    added_scopes = set(new_scopes) - set(old_scopes)
    removed_scopes = set(old_scopes) - set(new_scopes)
    added_oos = set(new_outofscopes) - set(old_outofscopes)
    removed_oos = set(old_outofscopes) - set(new_outofscopes)
    
    logger.info(f"=== Diff for {handle} ===")
    if not any([added_scopes, removed_scopes, added_oos, removed_oos]):
        logger.info("  No changes detected.")
        return

    if added_scopes:
        logger.info(f"  [+] Added Scopes: {', '.join(added_scopes)}")
    if removed_scopes:
        logger.info(f"  [-] Removed Scopes: {', '.join(removed_scopes)}")
    if added_oos:
        logger.info(f"  [+] Added Out-Of-Scope: {', '.join(added_oos)}")
    if removed_oos:
        logger.info(f"  [-] Removed Out-Of-Scope: {', '.join(removed_oos)}")
    print("-" * 40)

def main():
    parser = argparse.ArgumentParser(description="Sync HackerOne program scopes to Watchtower JSONs.")
    parser.add_argument('--diff', action='store_true', help="Show differences without saving to file.")
    args = parser.parse_args()

    h1_user = os.getenv('H1_API_USERNAME')
    h1_token = os.getenv('H1_API_TOKEN')

    if not h1_user or not h1_token:
        logger.error("H1_API_USERNAME and H1_API_TOKEN environment variables must be set.")
        sys.exit(1)

    auth = HTTPBasicAuth(h1_user, h1_token)

    if not HANDLES_FILE.exists():
        logger.error(f"Handles file not found at {HANDLES_FILE}. Please create it and add handles line by line.")
        sys.exit(1)

    with open(HANDLES_FILE, 'r', encoding='utf-8') as f:
        handles = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    if not handles:
        logger.warning(f"No handles found in {HANDLES_FILE}.")
        sys.exit(0)

    for handle in handles:
        logger.info(f"Fetching structured scopes for: {handle} ...")
        new_scopes, new_outofscopes = fetch_h1_scopes(handle, auth)
        
        if new_scopes is None and new_outofscopes is None:
            continue # خطا قبلاً لاگ شده، پرش به برنامه بعدی
            
        target_json_path = Path(config.PROGRAMS_DIR) / f"{handle}.json"
        
        old_scopes = []
        old_outofscopes = []
        manual_override = False
        config_data = {}
        
        # خواندن فایل قبلی (اگر وجود داشت)
        if target_json_path.exists():
            try:
                with open(target_json_path, 'r', encoding='utf-8') as f:
                    old_data = json.load(f)
                    old_scopes = old_data.get('scopes', [])
                    old_outofscopes = old_data.get('outofscope', old_data.get('outofscopes', []))
                    manual_override = old_data.get('manual_override', False)
                    config_data = old_data.get('config', {})
            except json.JSONDecodeError:
                logger.error(f"[{handle}] Existing JSON is invalid. Overwriting unless --diff is set.")

        if args.diff:
            print_diff(handle, old_scopes, old_outofscopes, new_scopes, new_outofscopes)
            continue
            
        if manual_override:
            logger.warning(f"[{handle}] 'manual_override' is set to true in {target_json_path.name}. Skipping update.")
            if new_scopes != old_scopes or new_outofscopes != old_outofscopes:
                logger.info(f"[{handle}] (Changes exist, but skipped due to manual_override)")
            continue

        # بررسی اینکه آیا اصلاً نیازی به آپدیت هست؟
        if set(old_scopes) == set(new_scopes) and set(old_outofscopes) == set(new_outofscopes):
            logger.info(f"[{handle}] No changes needed. Up to date.")
            continue

        # ساخت آبجکت نهایی
        final_data = {
            "program_name": handle,
            "scopes": new_scopes,
            "outofscope": new_outofscopes,
            "config": config_data # حفظ تنظیمات کانفیگ قبلی (مثل headers یا throttling)
        }

        # ذخیره فایل
        try:
            with open(target_json_path, 'w', encoding='utf-8') as f:
                json.dump(final_data, f, indent=2, ensure_ascii=False)
            logger.info(f"[{handle}] Successfully updated {target_json_path.name}")
        except Exception as e:
            logger.error(f"[{handle}] Failed to write file: {e}")

if __name__ == "__main__":
    main()