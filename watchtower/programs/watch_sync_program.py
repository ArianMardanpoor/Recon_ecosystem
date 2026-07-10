#!/usr/bin/env python3
import os
import sys
import json
import logging
import re
from pathlib import Path

# اضافه کردن مسیر روت پروژه به sys.path برای ایمپورت‌های تمیزتر
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# ایمپورت تابع delete_program اضافه شد
from database.db import upsert_program, delete_program
import config

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SyncProgram")

def parse_scopes(scopes):
    """
    وایلدکاردها رو بررسی میکنه و دو خروجی میده:
    1. recon_domains: دامین‌های پایه برای اسکن (بخش بعد از آخرین ستاره)
    2. regex_patterns: پترن‌های رجکس برای فیلتر نتایج نهایی
    """
    recon_domains = set()
    regex_patterns = []

    for scope in scopes:
        # تبدیل وایلدکارد به رجکس (دات -> \. و ستاره -> .*)
        regex_str = scope.replace('.', r'\.').replace('*', '.*')
        regex_patterns.append(f"^{regex_str}$")

        # استخراج دامین پایه برای مراحل ریکان
        if '*' in scope:
            # گرفتن بخش بعد از آخرین ستاره و حذف دات‌های اضافی
            base = scope.split('*')[-1].strip('.')
            if base:
                recon_domains.add(base)
        else:
            recon_domains.add(scope)

    return list(recon_domains), regex_patterns

def scan_json(directory: Path):
    """اسکن دایرکتوری برای فایل‌های JSON برنامه‌ها"""
    if not directory.exists() or not directory.is_dir():
        logger.error(f"Directory not found or invalid: {directory}")
        return
    
    for file_path in directory.glob('*.json'):
        logger.info(f"Processing program file: {file_path.name}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                data = json.load(file)
                
                program_name = data.get("program_name")
                scopes = data.get("scopes", [])
                
                # پشتیبانی از هر دو فرمت outofscope و outofscopes
                outofscopes = data.get("outofscope", data.get("outofscopes", []))
                config_data = data.get("config", {})
                
                if program_name:
                    # تفکیک اسکوپ‌های ریکان و ساخت رجکس‌ها
                    recon_scopes, regex_filters = parse_scopes(scopes)
                    
                    # ذخیره رجکس‌ها و اسکوپ‌های اصلی توی کانفیگ برای استفاده ابزارهای بعدی
                    config_data["regex_filters"] = regex_filters
                    config_data["original_scopes"] = scopes

                    # پاس دادن دامین‌های تمیز شده (recon_scopes) به دیتابیس
                    upsert_program(program_name, recon_scopes, outofscopes, config_data)
                    logger.info(f"Successfully upserted: {program_name}")
                else:
                    logger.warning(f"File {file_path.name} is missing 'program_name' field. Skipped.")
                    
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in file {file_path.name}: {e}")
        except Exception as e:
            logger.exception(f"Unexpected error processing {file_path.name}: {e}")

def scan_skipped(directory: Path):
    skipped_dir = directory / "skipped"
    processed_dir = skipped_dir / "processed"

    if not skipped_dir.exists() or not skipped_dir.is_dir():
        logger.info("Skipped directory not found. Skipping deletion process.")
        return

    processed_dir.mkdir(exist_ok=True)

    for file_path in skipped_dir.glob('*.json'):
        logger.info(f"Processing skipped file: {file_path.name}")

        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                data = json.load(file)
                program_name = data.get("program_name")

                if program_name:
                    delete_program(program_name)
                    logger.info(f"Successfully deleted from database: {program_name}")
                    # فایل رو به پوشه‌ی processed منتقل کن تا دوباره اجرا نشه
                    file_path.rename(processed_dir / file_path.name)
                else:
                    logger.warning(f"File {file_path.name} in skipped dir lacks 'program_name'.")

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in skipped file {file_path.name}: {e}")
        except Exception as e:
            logger.exception(f"Unexpected error processing skipped {file_path.name}: {e}")
            
if __name__ == "__main__":
    base_script_dir = Path(__file__).parent
    scan_dir = base_script_dir / "Programs"

    logger.info(f"Starting sync from directory: {scan_dir.resolve()}")
    scan_json(scan_dir)

    logger.info(f"Checking for skipped programs in: {(base_script_dir / 'skipped').resolve()}")
    scan_skipped(base_script_dir)