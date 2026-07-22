#!/usr/bin/env python3
import os
import sys
import json
import logging
from pathlib import Path

# اضافه کردن مسیر روت پروژه به sys.path برای ایمپورت‌های تمیزتر
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# اضافه کردن Programs به ایمپورت‌ها برای کوئری گرفتن از دیتابیس[cite: 1, 2]
from database.db import upsert_program, delete_program, Programs

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')[cite: 1]
logger = logging.getLogger("SyncProgram")[cite: 1]

# ------------------------------------------------------------------
# مسیرها به صورت مستقیم نسبت به خود اسکریپت ست شدن (بدون config)
# دایرکتوری‌های مربوط به skipped به طور کامل حذف شدند[cite: 1]
# ------------------------------------------------------------------
BASE_DIR = Path(__file__).parent[cite: 1]
PROGRAMS_DIR = BASE_DIR / "Programs"[cite: 1]


def parse_scopes(scopes):
    """
    وایلدکاردها رو بررسی میکنه و دو خروجی میده:
    1. recon_domains: دامین‌های پایه برای اسکن (بخش بعد از آخرین ستاره)
    2. regex_patterns: پترن‌های رجکس برای فیلتر نتایج نهایی
    """
    recon_domains = set()[cite: 1]
    regex_patterns = [][cite: 1]

    for scope in scopes:[cite: 1]
        # تبدیل وایلدکارد به رجکس (دات -> \. و ستاره -> .*)[cite: 1]
        regex_str = scope.replace('.', r'\.').replace('*', '.*')[cite: 1]
        regex_patterns.append(f"^{regex_str}$")[cite: 1]

        # استخراج دامین پایه برای مراحل ریکان[cite: 1]
        if '*' in scope:[cite: 1]
            base = scope.split('*')[-1].strip('.')[cite: 1]
            if base:[cite: 1]
                recon_domains.add(base)[cite: 1]
        else:
            recon_domains.add(scope)[cite: 1]

    return list(recon_domains), regex_patterns[cite: 1]


def scan_json(directory: Path):
    """اسکن دایرکتوری برای فایل‌های JSON برنامه‌ها (افزودن/آپدیت) و برگرداندن لیست برنامه‌های فعال"""
    active_programs = set()

    if not directory.exists() or not directory.is_dir():[cite: 1]
        logger.error(f"Directory not found or invalid: {directory.resolve()}")[cite: 1]
        return active_programs

    json_files = list(directory.glob('*.json'))[cite: 1]
    if not json_files:[cite: 1]
        logger.warning(f"No JSON files found in: {directory.resolve()}")[cite: 1]
        return active_programs

    logger.info(f"Found {len(json_files)} program file(s) in: {directory.resolve()}")[cite: 1]

    for file_path in json_files:[cite: 1]
        logger.info(f"Processing program file: {file_path.name}")[cite: 1]

        try:
            with open(file_path, 'r', encoding='utf-8') as file:[cite: 1]
                data = json.load(file)[cite: 1]

                program_name = data.get("program_name")[cite: 1]
                scopes = data.get("scopes", [])[cite: 1]

                # پشتیبانی از هر دو فرمت outofscope و outofscopes[cite: 1]
                outofscopes = data.get("outofscope", data.get("outofscopes", []))[cite: 1]
                config_data = data.get("config", {})[cite: 1]

                if program_name:[cite: 1]
                    recon_scopes, regex_filters = parse_scopes(scopes)[cite: 1]

                    config_data["regex_filters"] = regex_filters[cite: 1]
                    config_data["original_scopes"] = scopes[cite: 1]

                    upsert_program(program_name, recon_scopes, outofscopes, config_data)[cite: 1]
                    logger.info(f"Successfully upserted: {program_name}")[cite: 1]
                    
                    # اضافه کردن اسم برنامه به لیست برنامه‌های فعال
                    active_programs.add(program_name)
                else:
                    logger.warning(f"File {file_path.name} is missing 'program_name' field. Skipped.")[cite: 1]

        except json.JSONDecodeError as e:[cite: 1]
            logger.error(f"Invalid JSON in file {file_path.name}: {e}")[cite: 1]
        except Exception as e:[cite: 1]
            logger.exception(f"Unexpected error processing {file_path.name}: {e}")[cite: 1]
            
    return active_programs


def remove_stale_programs(active_programs):
    """
    برنامه‌هایی که در دیتابیس هستند اما فایل JSON آن‌ها در دایرکتوری نیست را حذف می‌کند.
    """
    logger.info("Checking database for stale programs to delete...")
    
    try:
        # دریافت لیست تمام برنامه‌های موجود در کالکشن Programs
        db_programs = set(Programs.objects().distinct('program_name'))
        
        # پیدا کردن برنامه‌هایی که باید حذف شوند
        programs_to_delete = db_programs - active_programs
        
        if not programs_to_delete:
            logger.info("No stale programs found in the database. Everything is synced.")
            return

        for prog in programs_to_delete:
            logger.info(f"Program '{prog}' is missing from the directory. Deleting from database...")
            # استفاده از تابع موجود برای حذف آبشاری از تمام کالکشن‌ها[cite: 2]
            delete_program(prog)
            
    except Exception as e:
        logger.exception(f"Unexpected error while removing stale programs: {e}")


if __name__ == "__main__":[cite: 1]
    logger.info(f"Starting sync from directory: {PROGRAMS_DIR.resolve()}")[cite: 1]
    
    # مرحله اول: خواندن فایل‌ها و آپسرت کردن دیتابیس
    active_programs_in_dir = scan_json(PROGRAMS_DIR)
    
    # مرحله دوم: پاک‌سازی دیتابیس از برنامه‌هایی که فایلشون پاک شده
    if active_programs_in_dir:
        remove_stale_programs(active_programs_in_dir)
    else:
        logger.warning("No active programs found in directory. Skipping deletion to prevent accidental wipe.")

    logger.info("Sync finished.")[cite: 1]