#!/usr/bin/env python3
import os
from pathlib import Path

# استفاده از pathlib برای مدیریت بهتر و تمیزتر مسیرها
BASE_DIR = Path(os.getenv('WATCHTOWER_BASE_DIR', Path.home() / 'watchtower')).resolve()

# تعریف دایرکتوری‌ها
DIRS = {
    "watch": BASE_DIR,
    "enum": BASE_DIR / 'enum',
    "ns": BASE_DIR / 'ns',
    "http": BASE_DIR / 'http',
    "nuclei": BASE_DIR / 'nuclei',
    "programs": BASE_DIR / 'programs',
    "logs": BASE_DIR / 'logs' # اضافه شدن پوشه لاگ
}

# ایجاد خودکار دایرکتوری‌ها
for name, dir_path in DIRS.items():
    dir_path.mkdir(parents=True, exist_ok=True)

# استخراج متغیرها برای استفاده در بقیه فایل‌ها
ENUM_DIR = DIRS["enum"]
NS_DIR = DIRS["ns"]
HTTP_DIR = DIRS["http"]
NUCLEI_DIR = DIRS["nuclei"]
PROGRAMS_DIR = DIRS["programs"]
LOGS_DIR = DIRS["logs"]