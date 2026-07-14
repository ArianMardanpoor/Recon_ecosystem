from mongoengine import Document, StringField, DateTimeField, ListField, DictField, IntField, BooleanField, connect
from mongoengine.connection import get_connection
from pymongo.errors import ConnectionFailure
from pymongo import UpdateOne 
from datetime import datetime
import tldextract
import os
import sys
import re
from dotenv import load_dotenv

# ایمپورت notify با مسیر نسبی
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from utils.notify import queue_new_http, queue_http_change

def current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ==========================================
# Database Connection Setup & Validation
# ==========================================
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError

# --- بارگذاری متغیرهای محیطی ---
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
load_dotenv(os.path.join(BASE_DIR, '.env'))

MONGO_URI = os.getenv("MONGO_URI")

if not MONGO_URI:
    print("[!] CRITICAL: MONGO_URI is not set in the .env file! Please check your configuration.", file=sys.stderr)
    sys.exit(1)
# -------------------------------

try:
    # اضافه کردن تایم‌اوت ۳ ثانیه‌ای برای انتخاب سرور
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
    
    # یک پینگ صوری به دیتابیس بزن تا مجبور بشه همین الان اتصال رو تست کنه
    client.admin.command('ping')
    print("[+] MongoDB connected successfully!")
    
except ServerSelectionTimeoutError as e:
    import sys
    print(f"[!] CRITICAL: MongoDB is down or unreachable! Details: {e}", file=sys.stderr)
    sys.exit(1)
    
connect_kwargs = {
    "db": "watchtower",
    "host": MONGO_URI,
    "alias": "default",
    "serverSelectionTimeoutMS": 60000
}

# اجبار استفاده از TLS/SSL برای کلاسترهای Atlas
if MONGO_URI.startswith("mongodb+srv://"):
    connect_kwargs["tls"] = True

# اتصال به MongoDB
connect(**connect_kwargs)

# ... (ادامه کدها شامل check_db_connection و مدل‌ها بدون تغییر) ...