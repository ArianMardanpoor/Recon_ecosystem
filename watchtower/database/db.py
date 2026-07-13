from mongoengine import Document, StringField, DateTimeField, ListField, DictField, IntField, BooleanField, connect
from mongoengine.connection import get_connection
from pymongo.errors import ConnectionFailure
from pymongo import UpdateOne 
from datetime import datetime
import tldextract
import os
import sys
import re

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

# کدهای بررسی فرمت تو که بالاتر بود...

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

def check_db_connection():
    """
    بررسی سلامت اتصال به دیتابیس. 
    این تابع باید در app.py قبل از app.run() فراخوانی شود.
    """
    try:
        client = get_connection(alias="default")
        client.admin.command('ping')
        print(f"[{current_time()}] Database health-check passed successfully.")
    except ConnectionFailure as e:
        raise RuntimeError(f"CRITICAL: Failed to connect to MongoDB. Check your network, MONGO_URI, or Atlas IP Access List. Details: {e}")
    except Exception as e:
        raise RuntimeError(f"CRITICAL: Unexpected error during database health-check: {e}")

def get_domain_name(url):
    """استخراج دامنه اصلی از URL یا ساب‌دامین"""
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}"

def is_in_scope(subdomain, scopes, outofscopes, regex_filters=None):
    """بررسی اینکه ساب‌دامین در scope است یا خیر، با پشتیبانی از رجکس"""
    domain = get_domain_name(subdomain)
    
    # چک کردن out of scope
    for oos in outofscopes:
        if oos in subdomain or subdomain == oos:
            return False
            
    # چک کردن با رجکس (اگر در کانفیگ تعریف شده باشد - وایلدکاردهای پیچیده)
    if regex_filters:
        for pattern in regex_filters:
            if re.match(pattern, subdomain):
                return True
        return False # اگر رجکس داریم ولی مچ نشده، یعنی خارج از اسکوپ است
    
    # چک کردن scope عادی (برای برنامه‌های بدون وایلدکارد پیچیده)
    for scope in scopes:
        if subdomain.endswith(scope) or subdomain == scope:
            return True
    
    return False

# ==========================================
# Database Models
# ==========================================

class Programs(Document):
    program_name = StringField(required=True, unique=True)
    created_date = DateTimeField(default=datetime.now)
    config = DictField(default={})
    scopes = ListField(StringField(), default=[])
    outofscopes = ListField(StringField(), default=[])
    
    meta = {
        'collection': 'programs',
        'indexes': [
            {'fields': ['program_name'], 'unique': True}
        ]
    }

class Subdomains(Document):
    program_name = StringField(required=True)
    subdomain = StringField(required=True)
    scope = StringField(required=True)
    providers = ListField(StringField(), default=[])
    tested = BooleanField(default=False)
    last_update = DateTimeField(default=datetime.now)
    created_date = DateTimeField(default=datetime.now)
    
    meta = {
        'collection': 'subdomains',
        'indexes': [
            {'fields': ['program_name', 'subdomain'], 'unique': True}
        ]
    }

class LiveSubdomains(Document):
    program_name = StringField(required=True)
    subdomain = StringField(required=True, unique=True)
    scope = StringField(required=True)
    ips = ListField(StringField(), default=[])
    cdn = StringField(default="")
    tested = BooleanField(default=False)
    created_date = DateTimeField(default=datetime.now)
    last_update = DateTimeField(default=datetime.now)
    
    meta = {
        'collection': 'live_subdomains',
        'indexes': [
            {'fields': ['program_name', 'subdomain'], 'unique': True}
        ]
    }

class Http(Document):
    program_name = StringField(required=True)
    subdomain = StringField(required=True, unique=True)
    scope = StringField(required=True)
    ips = ListField(StringField(), default=[])
    tech = ListField(StringField(), default=[])
    title = StringField(default="")
    status_code = IntField(default=0)
    headers = DictField(default={})
    url = StringField()
    final_url = StringField()
    favicon = StringField()
    tested = BooleanField(default=False)
    
    # New Recon/XSS Pipeline Artifacts
    passive_urls = ListField(StringField(), default=[])
    crawled_urls = ListField(StringField(), default=[])
    discovered_params = ListField(StringField(), default=[])
    last_scan_date = DateTimeField(default=None, null=True)
    scan_status = StringField(default="not_scanned")
    findings = ListField(DictField(), default=[])
    
    last_update = DateTimeField(default=datetime.now)
    created_date = DateTimeField(default=datetime.now)
    
    meta = {
        'collection': 'http_services',
        'indexes': [
            {'fields': ['program_name', 'subdomain'], 'unique': True}
        ]
    }

# ==========================================
# Database Operations
# ==========================================

def delete_program(program_name):
    """حذف کامل یک برنامه و تمام داده‌های مرتبط با آن از دیتابیس"""
    try:
        Programs.objects(program_name=program_name).delete()
        Subdomains.objects(program_name=program_name).delete()
        LiveSubdomains.objects(program_name=program_name).delete()
        Http.objects(program_name=program_name).delete()
        print(f"[{current_time()}] Deleted program and all related data: {program_name}")
        return True
    except Exception as e:
        print(f"[{current_time()}] Error deleting program {program_name}: {e}")
        return False

def upsert_program(program_name, scopes, outofscopes, config=None):
    """درج یا بروزرسانی برنامه"""
    if config is None:
        config = {}
    
    program = Programs.objects(program_name=program_name).first()
    
    if program:
        program.config = config
        program.scopes = scopes
        program.outofscopes = outofscopes
        program.save()
        print(f"[{current_time()}] Updated program: {program_name}")
    else:
        new_program = Programs(
            program_name=program_name,
            created_date=datetime.now(),
            config=config,
            scopes=scopes,
            outofscopes=outofscopes
        )
        new_program.save()
        print(f"[{current_time()}] Inserted new program: {program_name}")

def upsert_subdomain(program_name, subdomain_name, provider):
    """درج یا بروزرسانی یک ساب‌دامین تکی با بررسی scope"""
    program = Programs.objects(program_name=program_name).first()
    
    if not program:
        print(f"[{current_time()}] Program not found: {program_name}")
        return False
    
    regex_filters = program.config.get("regex_filters", [])
    
    if not is_in_scope(subdomain_name, program.scopes, program.outofscopes, regex_filters):
        print(f"[{current_time()}] Subdomain out of scope: {subdomain_name}")
        return False
    
    scope_domain = get_domain_name(subdomain_name)
    existing = Subdomains.objects(program_name=program_name, subdomain=subdomain_name).first()
    
    if existing:
        if provider not in existing.providers:
            existing.providers.append(provider)
            print(f"[{current_time()}] Added provider to subdomain: {subdomain_name}")
        existing.last_update = datetime.now()
        existing.save()
    else:
        new_subdomain = Subdomains(
            program_name=program_name,
            subdomain=subdomain_name,
            scope=scope_domain,
            providers=[provider],
            created_date=datetime.now(),
            last_update=datetime.now()
        )
        new_subdomain.save()
        print(f"[{current_time()}] Inserted new subdomain: {subdomain_name}")
    
    return True

def bulk_upsert_subdomains(program_name, subdomains_list, provider):
    """درج یا بروزرسانی گروهی ساب‌دامین‌ها برای سرعت فوق‌العاده بالا"""
    program = Programs.objects(program_name=program_name).first()
    
    if not program:
        print(f"[{current_time()}] Program not found: {program_name}")
        return False
        
    operations = []
    valid_subs = 0
    regex_filters = program.config.get("regex_filters", [])
    
    for sub in subdomains_list:
        sub = sub.strip().lower()
        if not sub: continue
        
        if not is_in_scope(sub, program.scopes, program.outofscopes, regex_filters):
            continue
            
        scope_domain = get_domain_name(sub)
        valid_subs += 1
        
        operations.append(
            UpdateOne(
                {'program_name': program_name, 'subdomain': sub},
                {
                    '$setOnInsert': {
                        'scope': scope_domain,
                        'created_date': datetime.now(),
                        'tested': False
                    },
                    '$addToSet': {'providers': provider},
                    '$set': {'last_update': datetime.now()}
                },
                upsert=True
            )
        )
    
    if operations:
        collection = Subdomains._get_collection()
        collection.bulk_write(operations, ordered=False)
        print(f"[{current_time()}] Bulk Upsert: {valid_subs} domains processed for {program_name} by {provider}")
    
    return True

def upsert_live(obj):
    """درج یا بروزرسانی ساب‌دامین زنده"""
    program = Programs.objects(scopes__in=[obj.get('scope')]).first()
    
    if not program:
        print(f"[{current_time()}] Program not found for scope: {obj.get('scope')}")
        return False
    
    existing = LiveSubdomains.objects(subdomain=obj.get('subdomain')).first()
    
    if existing:
        ips_changed = False
        if obj.get('ips'):
            new_ips = sorted(obj.get('ips', []))
            old_ips = sorted(existing.ips)
            if new_ips != old_ips:
                existing.ips = new_ips
                ips_changed = True
        
        if ips_changed or obj.get('cdn') != existing.cdn:
            existing.last_update = datetime.now()
            if obj.get('cdn'):
                existing.cdn = obj.get('cdn')
            existing.save()
            print(f"[{current_time()}] Updated live subdomain: {obj.get('subdomain')}")
    else:
        new_live = LiveSubdomains(
            program_name=program.program_name,
            subdomain=obj.get('subdomain'),
            scope=obj.get('scope'),
            ips=obj.get('ips', []),
            cdn=obj.get('cdn', ''),
            created_date=datetime.now(),
            last_update=datetime.now()
        )
        new_live.save()
        print(f"[{current_time()}] Inserted new live subdomain: {obj.get('subdomain')}")
    
    return True

def upsert_http(obj):
    """درج یا بروزرسانی اطلاعات HTTP"""
    program = Programs.objects(scopes__in=[obj.get('scope')]).first()
    
    if not program:
        print(f"[{current_time()}] Program not found for scope: {obj.get('scope')}")
        return False
    
    existing = Http.objects(subdomain=obj.get('subdomain')).first()
    
    if existing:
        changes = []
        
        if obj.get('title') and existing.title != obj.get('title'):
            changes.append(f"title: {existing.title} -> {obj.get('title')}")
            existing.title = obj.get('title')
        
        if obj.get('status_code') and existing.status_code != obj.get('status_code'):
            changes.append(f"status_code: {existing.status_code} -> {obj.get('status_code')}")
            existing.status_code = obj.get('status_code')
        
        if obj.get('favicon') and existing.favicon != obj.get('favicon'):
            changes.append("favicon changed")
            existing.favicon = obj.get('favicon')
        
        if changes:
            print(f"[{current_time()}] Changes detected for {obj.get('subdomain')}: {', '.join(changes)}")
            queue_http_change(
                program_name=existing.program_name,
                url=obj.get('url') or obj.get('subdomain'),
                changes=changes,
            )
        
        existing.ips = obj.get('ips', [])
        existing.tech = obj.get('tech', [])
        existing.headers = obj.get('headers', {})
        existing.url = obj.get('url', '')
        existing.final_url = obj.get('final_url', '')
        existing.last_update = datetime.now()
        existing.save()
    else:
        new_http = Http(
            program_name=program.program_name,
            subdomain=obj.get('subdomain'),
            scope=obj.get('scope'),
            ips=obj.get('ips', []),
            tech=obj.get('tech', []),
            title=obj.get('title', ''),
            status_code=obj.get('status_code', 0),
            headers=obj.get('headers', {}),
            url=obj.get('url', ''),
            final_url=obj.get('final_url', ''),
            favicon=obj.get('favicon', ''),
            created_date=datetime.now(),
            last_update=datetime.now()
        )
        new_http.save()
        print(f"[{current_time()}] Inserted new HTTP service: {obj.get('subdomain')}")

        queue_new_http(
            program_name=program.program_name,
            url=obj.get('url') or obj.get('subdomain'),
            status_code=obj.get('status_code', 0),
            title=obj.get('title', ''),
            tech=obj.get('tech', []),
            ips=obj.get('ips', []),
        )
    
    return True

def upsert_scan_artifacts(subdomain, passive_urls=None, crawled_urls=None, discovered_params=None):
    """درج یا بروزرسانی نتایج پایپ‌لاین اسکن برای یک ساب‌دامین"""
    http_doc = Http.objects(subdomain=subdomain).first()
    
    if not http_doc:
        print(f"[{current_time()}] Warning: Cannot upsert scan artifacts. Http doc not found for: {subdomain}")
        return False
        
    if passive_urls is not None:
        http_doc.passive_urls = list(set(passive_urls))
    if crawled_urls is not None:
        http_doc.crawled_urls = list(set(crawled_urls))
    if discovered_params is not None:
        http_doc.discovered_params = list(set(discovered_params))
        
    http_doc.last_update = datetime.now()
    http_doc.save()
    
    return True

def upsert_scan_findings(subdomain, findings_list, scan_status, force=False):
    """درج یا بروزرسانی یافته‌های آسیب‌پذیری پایپ‌لاین"""
    http_doc = Http.objects(subdomain=subdomain).first()
    
    if not http_doc:
        print(f"[{current_time()}] Warning: Cannot upsert findings. Http doc not found for: {subdomain}")
        return False

    confidence_weights = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
    
    # Merge findings deduped by (parameter, discovery_source, reflection_type)
    merged_findings = {}
    for f in http_doc.findings:
        key = (f.get('parameter'), f.get('discovery_source'), f.get('reflection_type'))
        merged_findings[key] = f

    for new_f in findings_list:
        key = (new_f.get('parameter'), new_f.get('discovery_source'), new_f.get('reflection_type'))
        if key in merged_findings:
            existing_conf_val = confidence_weights.get(str(merged_findings[key].get('confidence')).upper(), 0)
            new_conf_val = confidence_weights.get(str(new_f.get('confidence')).upper(), 0)
            
            # Keep the one with higher confidence
            if new_conf_val > existing_conf_val:
                merged_findings[key] = new_f
        else:
            merged_findings[key] = new_f
            
    http_doc.findings = list(merged_findings.values())
    
    calculated_status = "clean"
    if http_doc.findings:
        calculated_status = "findings"
        if any(str(f.get('confidence')).upper() == 'HIGH' for f in http_doc.findings):
            calculated_status = "confirmed_vuln"
            
    if not force and http_doc.scan_status == "confirmed_vuln" and calculated_status != "confirmed_vuln":
        new_status = "confirmed_vuln"
    else:
        new_status = calculated_status
        
    http_doc.scan_status = new_status
    http_doc.last_scan_date = datetime.now()
    http_doc.last_update = datetime.now()
    http_doc.save()
    
    return True
