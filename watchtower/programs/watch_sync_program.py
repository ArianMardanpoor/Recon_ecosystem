#!/usr/bin/env python3
import os
import sys
import json
import logging
from pathlib import Path

# اضافه کردن مسیر روت پروژه به sys.path برای ایمپورت‌های تمیزتر
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.db import upsert_program, delete_program

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SyncProgram")

# ------------------------------------------------------------------
# مسیرها به صورت مستقیم نسبت به خود اسکریپت ست شدن (بدون config)
# ------------------------------------------------------------------
BASE_DIR = Path(__file__).parent
PROGRAMS_DIR = BASE_DIR / "Programs"
SKIPPED_DIR = BASE_DIR / "skipped"
SKIPPED_PROCESSED_DIR = SKIPPED_DIR / "processed"


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
            base = scope.split('*')[-1].strip('.')
            if base:
                recon_domains.add(base)
        else:
            recon_domains.add(scope)

    return list(recon_domains), regex_patterns


def scan_json(directory: Path):
    """اسکن دایرکتوری برای فایل‌های JSON برنامه‌ها (افزودن/آپدیت)"""
    if not directory.exists() or not directory.is_dir():
        logger.error(f"Directory not found or invalid: {directory.resolve()}")
        return

    json_files = list(directory.glob('*.json'))
    if not json_files:
        logger.warning(f"No JSON files found in: {directory.resolve()}")
        return

    logger.info(f"Found {len(json_files)} program file(s) in: {directory.resolve()}")

    for file_path in json_files:
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
                    recon_scopes, regex_filters = parse_scopes(scopes)

                    config_data["regex_filters"] = regex_filters
                    config_data["original_scopes"] = scopes

                    upsert_program(program_name, recon_scopes, outofscopes, config_data)
                    logger.info(f"Successfully upserted: {program_name}")
                else:
                    logger.warning(f"File {file_path.name} is missing 'program_name' field. Skipped.")

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in file {file_path.name}: {e}")
        except Exception as e:
            logger.exception(f"Unexpected error processing {file_path.name}: {e}")


def scan_skipped():
    """
    اسکن دایرکتوری skipped برای حذف برنامه‌ها از دیتابیس.
    بعد از حذف موفق، فایل به skipped/processed منتقل می‌شه تا
    دفعه‌ی بعد دوباره پردازش نشه.
    """
    if not SKIPPED_DIR.exists() or not SKIPPED_DIR.is_dir():
        logger.info(f"Skipped directory not found: {SKIPPED_DIR.resolve()}. Skipping deletion process.")
        return

    json_files = list(SKIPPED_DIR.glob('*.json'))
    if not json_files:
        logger.info("No skipped files to process.")
        return

    SKIPPED_PROCESSED_DIR.mkdir(exist_ok=True)

    for file_path in json_files:
        logger.info(f"Processing skipped file: {file_path.name}")

        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                data = json.load(file)
                program_name = data.get("program_name")

                if program_name:
                    delete_program(program_name)
                    logger.info(f"Successfully deleted from database: {program_name}")

                    # جابجایی فایل به processed تا دیگه دوباره خونده نشه
                    destination = SKIPPED_PROCESSED_DIR / file_path.name
                    file_path.rename(destination)
                    logger.info(f"Moved to: {destination.resolve()}")
                else:
                    logger.warning(f"File {file_path.name} in skipped dir lacks 'program_name'.")

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in skipped file {file_path.name}: {e}")
        except Exception as e:
            logger.exception(f"Unexpected error processing skipped {file_path.name}: {e}")


if __name__ == "__main__":
    logger.info(f"Starting sync from directory: {PROGRAMS_DIR.resolve()}")
    scan_json(PROGRAMS_DIR)

    logger.info(f"Checking for skipped programs in: {SKIPPED_DIR.resolve()}")
    scan_skipped()

    logger.info("Sync finished.")