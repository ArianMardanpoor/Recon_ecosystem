#!/usr/bin/env python3
import os
import sys
import json
import logging
from pathlib import Path
import tldextract

# اضافه کردن مسیر روت پروژه به sys.path برای ایمپورت‌های تمیزتر
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# ایمپورت توابع دیتابیس از جمله bulk_upsert_subdomains برای درج مستقیم
from database.db import upsert_program, delete_program, Programs, bulk_upsert_subdomains
from utils.scope_classifier import classify_scope

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SyncProgram")

BASE_DIR = Path(__file__).parent
PROGRAMS_DIR = BASE_DIR / "Programs"

def parse_scopes(scopes):
    """
    اسکوپ‌ها را بررسی کرده و پنج خروجی می‌دهد:
    1. recon_domains: دامین‌های پایه برای اسکن
    2. regex_patterns: پترن‌های رجکس برای فیلتر نتایج نهایی
    3. pre_resolved_urls: آدرس‌های URL کامل
    4. ip_ranges: آدرس‌های IP و رنج‌های CIDR
    5. known_subdomains: ساب‌دامین‌های لیترال که باید مستقیم در دیتابیس درج شوند
    """
    recon_domains = set()
    regex_patterns = []
    pre_resolved_urls = set()
    ip_ranges = set()
    known_subdomains = set()

    for scope in scopes:
        # تبدیل وایلدکارد به رجکس
        regex_str = scope.replace('.', r'\.').replace('*', '.*')
        regex_patterns.append(f"^{regex_str}$")

        scope_type = classify_scope(scope)

        if scope_type == "url":
            pre_resolved_urls.add(scope)
        elif scope_type == "ip_or_cidr":
            ip_ranges.add(scope)
        elif scope_type == "wildcard":
            base = scope.split('*')[-1].strip('.')
            if base:
                recon_domains.add(base)
        elif scope_type == "literal_subdomain":
            known_subdomains.add(scope)
            
            # استخراج دامنه‌ی ریشه برای اطمینان از اینکه اگر خودش دامنه ریشه است (مثلاً cbre.com) همچنان enum شود
            ext = tldextract.extract(scope)
            root_domain = f"{ext.domain}.{ext.suffix}"
            if scope == root_domain:
                recon_domains.add(scope)
        else:
            recon_domains.add(scope)

    return list(recon_domains), regex_patterns, list(pre_resolved_urls), list(ip_ranges), list(known_subdomains)

def scan_json(directory: Path):
    """اسکن دایرکتوری برای فایل‌های JSON برنامه‌ها (افزودن/آپدیت) و برگرداندن لیست برنامه‌های فعال"""
    active_programs = set()

    if not directory.exists() or not directory.is_dir():
        logger.error(f"Directory not found or invalid: {directory.resolve()}")
        return active_programs

    json_files = list(directory.glob('*.json'))
    if not json_files:
        logger.warning(f"No JSON files found in: {directory.resolve()}")
        return active_programs

    logger.info(f"Found {len(json_files)} program file(s) in: {directory.resolve()}")

    for file_path in json_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                data = json.load(file)

                program_name = data.get("program_name")
                scopes = data.get("scopes", [])

                # پشتیبانی از هر دو فرمت outofscope و outofscopes
                outofscopes = data.get("outofscope", data.get("outofscopes", []))
                config_data = data.get("config", {})

                if program_name:
                    recon_scopes, regex_filters, pre_resolved_urls, ip_ranges, known_subdomains = parse_scopes(scopes)

                    config_data["regex_filters"] = regex_filters
                    config_data["original_scopes"] = scopes
                    config_data["pre_resolved_urls"] = pre_resolved_urls
                    config_data["ip_ranges"] = ip_ranges

                    upsert_program(program_name, recon_scopes, outofscopes, config_data)
                    
                    if known_subdomains:
                        bulk_upsert_subdomains(program_name, known_subdomains, provider="scope_literal")

                    logger.info(f"[{program_name}] {len(known_subdomains)} known literal subdomains inserted directly (bypassing enum), {len(recon_scopes)} domains queued for full enum")
                    
                    active_programs.add(program_name)
                else:
                    logger.warning(f"File {file_path.name} is missing 'program_name' field. Skipped.")

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in file {file_path.name}: {e}")
        except Exception as e:
            logger.exception(f"Unexpected error processing {file_path.name}: {e}")
            
    return active_programs

def remove_stale_programs(active_programs):
    """برنامه‌هایی که در دیتابیس هستند اما فایل JSON آن‌ها در دایرکتوری نیست را حذف می‌کند."""
    logger.info("Checking database for stale programs to delete...")
    
    try:
        db_programs = set(Programs.objects().distinct('program_name'))
        programs_to_delete = db_programs - active_programs
        
        if not programs_to_delete:
            logger.info("No stale programs found in the database. Everything is synced.")
            return

        for prog in programs_to_delete:
            logger.info(f"Program '{prog}' is missing from the directory. Deleting from database...")
            delete_program(prog)
            
    except Exception as e:
        logger.exception(f"Unexpected error while removing stale programs: {e}")

if __name__ == "__main__":
    logger.info(f"Starting sync from directory: {PROGRAMS_DIR.resolve()}")
    
    active_programs_in_dir = scan_json(PROGRAMS_DIR)
    
    if active_programs_in_dir:
        remove_stale_programs(active_programs_in_dir)
    else:
        logger.warning("No active programs found in directory. Skipping deletion to prevent accidental wipe.")

    logger.info("Sync finished.")