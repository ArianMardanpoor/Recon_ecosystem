#!/usr/bin/env python3
"""
WatchTower - Screenshot Module
Takes screenshots of HTTP services using Playwright (Chromium).
Saves directly to MongoDB GridFS.

Requires: playwright installed
  pip install playwright && playwright install chromium

Usage:
  python3 watch_screenshot.py                            # All Http documents
  python3 watch_screenshot.py --program name1,name2      # Specific programs
  python3 watch_screenshot.py --fresh                    # Only docs updated in last 24h
  python3 watch_screenshot.py --force                    # Retake all, skip nothing
"""

import sys
import os
import argparse
from datetime import datetime, timedelta
from playwright.sync_api import sync_playwright

# Setup sys.path to allow importing from watchtower root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.db import Http, upsert_screenshot, current_time
from utils.cli_helpers import parse_program_filter


class colors:
    GRAY = "\033[90m"
    RESET = "\033[0m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"


PAGE_TIMEOUT = 8000
BROWSER_TIMEOUT = 30000
RESTART_BROWSER_EVERY = 50


def safe_screenshot(browser, url: str):
    """
    Take screenshot of a single URL and return bytes directly.
    Returns bytes if successful, None otherwise.
    """
    page = None
    try:
        page = browser.new_page()
        page.set_default_navigation_timeout(PAGE_TIMEOUT)
        page.goto(url, timeout=PAGE_TIMEOUT, wait_until="domcontentloaded")
        # Capturing bytes by omitting the 'path' argument
        image_bytes = page.screenshot(full_page=True)
        page.close()
        return image_bytes
    except Exception:
        try:
            if page: page.close()
        except:
            pass
        return None


def take_screenshots(docs, total: int, force: bool = False) -> dict:
    """
    Iterate over Http documents and capture screenshots.
    Returns stats dict.
    """
    if total == 0:
        return {"screenshots": 0, "errors": 0, "skipped": 0}

    stats = {"screenshots": 0, "errors": 0, "skipped": 0}

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            timeout=BROWSER_TIMEOUT,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu", "--disable-setuid-sandbox"]
        )

        for i, doc in enumerate(docs, 1):
            subdomain = doc.subdomain

            # Skip if already has screenshot and not forced
            if doc.screenshot_file_id and not force:
                stats["skipped"] += 1
                print(f"     {colors.GRAY}[{i}/{total}] {subdomain} (skipped){colors.RESET}")
                continue

            print(f"     {colors.GRAY}[{i}/{total}] {subdomain}...{colors.RESET}")

            # Fallback chain for the URL
            url = doc.url or doc.final_url or f"https://{subdomain}"

            # Try original/HTTPS URL
            image_bytes = safe_screenshot(browser, url)
            if image_bytes:
                if upsert_screenshot(subdomain, image_bytes):
                    stats["screenshots"] += 1
                    print(f"     {colors.GREEN}✅ {subdomain}{colors.RESET}")
                    continue

            # HTTP fallback logic
            if url.startswith("https://"):
                http_url = url.replace("https://", "http://", 1)
                image_bytes = safe_screenshot(browser, http_url)
                if image_bytes:
                    if upsert_screenshot(subdomain, image_bytes):
                        stats["screenshots"] += 1
                        print(f"     {colors.GREEN}✅ {subdomain} (http fallback){colors.RESET}")
                        continue

            stats["errors"] += 1
            print(f"     {colors.YELLOW}⚠️ Failed: {subdomain}{colors.RESET}")

            # Restart browser periodically to prevent zombie processes/memory leaks
            if i % RESTART_BROWSER_EVERY == 0:
                try: browser.close()
                except: pass
                
                browser = p.chromium.launch(
                    headless=True, 
                    timeout=BROWSER_TIMEOUT,
                    args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu", "--disable-setuid-sandbox"]
                )

        try: browser.close()
        except: pass

    return stats


def main():
    parser = argparse.ArgumentParser(description="WatchTower Screenshot Module")
    parser.add_argument("--program", type=str, help="Comma-separated list of programs to filter by")
    parser.add_argument("--fresh", action="store_true", help="Only process documents updated in the last 24 hours")
    parser.add_argument("--force", action="store_true", help="Retake screenshot even if screenshot_file_id is already set")
    args = parser.parse_args()

    # Build the MongoEngine query
    query = Http.objects()

    if args.program:
        programs = parse_program_filter(args.program)
        if programs:
            query = query.filter(program_name__in=programs)

    if args.fresh:
        twenty_four_hours_ago = datetime.now() - timedelta(days=1)
        query = query.filter(last_update__gte=twenty_four_hours_ago)

    total_docs = query.count()
    
    mode_text = "Fresh" if args.fresh else "All"
    prog_text = f"Program: {args.program}" if args.program else "All Programs"
    force_text = " [Force]" if args.force else ""
    
    print(f"{colors.CYAN}[{current_time()}] WatchTower — Screenshot ({mode_text} | {prog_text}){force_text}{colors.RESET}")
    print(f"     {colors.CYAN}📋 Found {total_docs} HTTP target(s) matching criteria{colors.RESET}\n")

    if total_docs == 0:
        print(f"{colors.YELLOW}⚠️ No targets found to process.{colors.RESET}")
        sys.exit(0)

    # Execute screenshot logic
    stats = take_screenshots(query, total_docs, force=args.force)

    # Final Summary
    print(f"\n{colors.GREEN}{'='*50}{colors.RESET}")
    print(f"[{current_time()}] Screenshot module done: {stats['screenshots']} taken, {stats['errors']} errors, {stats['skipped']} skipped")


if __name__ == "__main__":
    main()