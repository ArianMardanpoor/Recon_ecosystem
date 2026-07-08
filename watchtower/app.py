#!/usr/bin/env python3
"""
Watchtower API - Full-Featured Recon Dashboard Backend
Supports rich multi-field filtering across all asset types
"""
import os
import re
from flask import Flask, request, jsonify
from datetime import datetime, timedelta
from functools import wraps
import signal
import sys
from mongoengine.queryset.visitor import Q
from database.db import (
    Programs, Subdomains, LiveSubdomains, Http,
    current_time
)

app = Flask(__name__)

API_TOKEN = os.getenv("WATCHTOWER_API_TOKEN", "a21uc0lzeTcK")


# ==========================================
# Auth & Helpers
# ==========================================

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-API-Token')
        if not token or token != API_TOKEN:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated


def validate_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False
    pattern = r'^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}[a-zA-Z0-9]$'
    return bool(re.match(pattern, domain))


def get_pagination_args():
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 100, type=int), 1000)
    return page, per_page


def parse_date(date_str):
    """تبدیل رشته تاریخ به datetime - فرمت: YYYY-MM-DD یا YYYY-MM-DDTHH:MM:SS"""
    if not date_str:
        return None
    for fmt in ('%Y-%m-%dT%H:%M:%S', '%Y-%m-%d'):
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    return None


def paginate_response(query, page, per_page, serializer):
    total = query.count()
    objects = query.skip((page - 1) * per_page).limit(per_page)
    return {
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': (total + per_page - 1) // per_page,
        'data': [serializer(obj) for obj in objects]
    }


# ==========================================
# Serializers
# ==========================================

def serialize_program(p):
    return {
        'program_name': p.program_name,
        'scopes': p.scopes,
        'outofscopes': p.outofscopes,
        'config': p.config or {},
        'created_date': p.created_date.strftime('%Y-%m-%d %H:%M:%S') if p.created_date else None
    }


def serialize_subdomain(sd):
    return {
        'subdomain': sd.subdomain,
        'program_name': sd.program_name,
        'scope': sd.scope,
        'providers': sd.providers,
        'tested': getattr(sd, 'tested', False),  # اضافه شد
        'created_date': sd.created_date.strftime('%Y-%m-%d %H:%M:%S') if sd.created_date else None,
        'last_update': sd.last_update.strftime('%Y-%m-%d %H:%M:%S') if sd.last_update else None
    }


def serialize_live(l):
    return {
        'subdomain': l.subdomain,
        'program_name': l.program_name,
        'scope': l.scope,
        'ips': l.ips,
        'cdn': l.cdn,
        'tested': getattr(l, 'tested', False),  # اضافه شد
        'created_date': l.created_date.strftime('%Y-%m-%d %H:%M:%S') if l.created_date else None,
        'last_update': l.last_update.strftime('%Y-%m-%d %H:%M:%S') if l.last_update else None
    }


def serialize_http(h, providers=None):
    return {
        'subdomain': h.subdomain,
        'program_name': h.program_name,
        'scope': h.scope,
        'url': h.url,
        'final_url': h.final_url,
        'title': h.title,
        'status_code': h.status_code,
        'tech': h.tech,
        'ips': h.ips,
        'headers': h.headers,
        'favicon': h.favicon,
        'tested': getattr(h, 'tested', False),  # اضافه شد
        'providers': providers or [],
        'created_date': h.created_date.strftime('%Y-%m-%d %H:%M:%S') if h.created_date else None,
        'last_update': h.last_update.strftime('%Y-%m-%d %H:%M:%S') if h.last_update else None
    }


# ==========================================
# Health
# ==========================================

@app.route('/api/health')
def health():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })


# ==========================================
# Programs
# ==========================================

@app.route('/api/programs', methods=['GET'])
@require_auth
def get_programs():
    """
    لیست برنامه‌ها با فیلتر
    Params:
      - search: جستجو در نام برنامه
    """
    programs = Programs.objects()
    search = request.args.get('search', '').strip()
    if search:
        programs = programs.filter(program_name__icontains=search)

    return jsonify({
        'total': programs.count(),
        'data': [serialize_program(p) for p in programs]
    })


@app.route('/api/programs/<program_name>', methods=['GET'])
@require_auth
def get_program(program_name):
    """جزئیات یک برنامه به همراه آمار کلی"""
    program = Programs.objects(program_name=program_name).first()
    if not program:
        return jsonify({'error': 'Program not found'}), 404

    stats = {
        'subdomains': Subdomains.objects(program_name=program_name).count(),
        'live': LiveSubdomains.objects(program_name=program_name).count(),
        'http': Http.objects(program_name=program_name).count(),
    }
    data = serialize_program(program)
    data['stats'] = stats
    return jsonify(data)


# ==========================================
# Subdomains — Rich Filtering
# ==========================================

@app.route('/api/subdomains', methods=['GET'])
@require_auth
def get_subdomains():
    """
    دریافت ساب‌دامین‌ها با فیلترهای پیشرفته.

    Query Params:
      - program       : نام برنامه (مستقیم)
      - programs      : چند برنامه جدا با کاما  (program1,program2)
      - scope         : دامنه اصلی (مثلاً example.com)
      - provider      : نام پروایدر (subfinder, amass, ...)
      - providers     : چند پروایدر جدا با کاما
      - search        : جستجو در نام ساب‌دامین (contains)
      - has_http      : true/false — آیا ساب‌دامین در جدول http هست؟
      - has_live      : true/false — آیا ساب‌دامین در جدول live_subdomains هست؟
      - created_after : YYYY-MM-DD
      - created_before: YYYY-MM-DD
      - updated_after : YYYY-MM-DD
      - updated_before: YYYY-MM-DD
      - only_new      : true — ساب‌دامین‌های ۲۴ ساعت اخیر
      - sort          : created_date / last_update / subdomain (پیشفرض: -created_date)
      - page, per_page
    """
    page, per_page = get_pagination_args()
    q = Subdomains.objects()

    # فیلتر برنامه
    program = request.args.get('program', '').strip()
    programs_csv = request.args.get('programs', '').strip()
    if program:
        q = q.filter(program_name=program)
    elif programs_csv:
        prog_list = [p.strip() for p in programs_csv.split(',') if p.strip()]
        q = q.filter(program_name__in=prog_list)

    # فیلتر scope
    scope = request.args.get('scope', '').strip()
    if scope:
        q = q.filter(scope=scope)

    # فیلتر provider
    provider = request.args.get('provider', '').strip()
    providers_csv = request.args.get('providers', '').strip()
    if provider:
        q = q.filter(providers=provider)
    elif providers_csv:
        prov_list = [p.strip() for p in providers_csv.split(',') if p.strip()]
        # ساب‌دامین‌هایی که حداقل یکی از این providerها رو دارن
        q = q.filter(providers__in=prov_list)

    # جستجو در نام
    search = request.args.get('search', '').strip()
    if search:
        q = q.filter(subdomain__icontains=search)

    # فیلتر تاریخ ایجاد
    created_after = parse_date(request.args.get('created_after', ''))
    if created_after:
        q = q.filter(created_date__gte=created_after)
    created_before = parse_date(request.args.get('created_before', ''))
    if created_before:
        q = q.filter(created_date__lte=created_before)

    # فیلتر تاریخ آپدیت
    updated_after = parse_date(request.args.get('updated_after', ''))
    if updated_after:
        q = q.filter(last_update__gte=updated_after)
    updated_before = parse_date(request.args.get('updated_before', ''))
    if updated_before:
        q = q.filter(last_update__lte=updated_before)

    # only_new: ۲۴ ساعت اخیر
    if request.args.get('only_new', '').lower() == 'true':
        q = q.filter(created_date__gte=datetime.now() - timedelta(hours=24))

    # فیلتر has_live / has_http — از طریق join روی subdomain
    has_live = request.args.get('has_live', '').lower()
    if has_live in ('true', 'false'):
        live_subs = set(LiveSubdomains.objects().distinct('subdomain'))
        if has_live == 'true':
            q = q.filter(subdomain__in=live_subs)
        else:
            q = q.filter(subdomain__nin=live_subs)

    has_http = request.args.get('has_http', '').lower()
    if has_http in ('true', 'false'):
        http_subs = set(Http.objects().distinct('subdomain'))
        if has_http == 'true':
            q = q.filter(subdomain__in=http_subs)
        else:
            q = q.filter(subdomain__nin=http_subs)

    # مرتب‌سازی
    sort_map = {
        'created_date': '+created_date',
        '-created_date': '-created_date',
        'last_update': '+last_update',
        '-last_update': '-last_update',
        'subdomain': '+subdomain',
        '-subdomain': '-subdomain',
    }
    sort = request.args.get('sort', '-created_date')
    order = sort_map.get(sort, '-created_date')
    q = q.order_by(order)

    return jsonify(paginate_response(q, page, per_page, serialize_subdomain))


# ==========================================
# Live Subdomains — Rich Filtering
# ==========================================

# ==========================================
# Live Subdomains — Rich Filtering
# ==========================================

@app.route('/api/lives', methods=['GET'])
@require_auth
def get_lives():
    """
    دریافت ساب‌دامین‌های زنده با فیلترهای پیشرفته.

    Query Params:
      - program       : نام برنامه
      - programs      : چند برنامه با کاما
      - scope         : دامنه اصلی
      - search        : جستجو در subdomain
      - ip            : فیلتر بر اساس یک IP خاص
      - has_cdn       : true/false — آیا CDN دارد؟
      - cdn           : نام CDN خاص (مثلاً cloudflare)
      - has_http      : true/false — آیا HTTP سرویس دارد؟
      - created_after, created_before
      - updated_after, updated_before
      - only_new      : true — ۲۴ ساعت اخیر
      - sort          : created_date / last_update / subdomain
      - page, per_page
    """
    page, per_page = get_pagination_args()
    q = LiveSubdomains.objects()

    program = request.args.get('program', '').strip()
    programs_csv = request.args.get('programs', '').strip()
    if program:
        q = q.filter(program_name=program)
    elif programs_csv:
        q = q.filter(program_name__in=[p.strip() for p in programs_csv.split(',') if p.strip()])

    scope = request.args.get('scope', '').strip()
    if scope:
        q = q.filter(scope=scope)

    search = request.args.get('search', '').strip()
    if search:
        q = q.filter(subdomain__icontains=search)

    ip = request.args.get('ip', '').strip()
    if ip:
        q = q.filter(ips=ip)

    has_cdn = request.args.get('has_cdn', '').lower()
    if has_cdn == 'true':
        q = q.filter(cdn__ne='').filter(cdn__exists=True)
    elif has_cdn == 'false':
        q = q.filter(Q(cdn='') | Q(cdn__exists=False))

    cdn = request.args.get('cdn', '').strip()
    if cdn:
        q = q.filter(cdn__icontains=cdn)

    created_after = parse_date(request.args.get('created_after', ''))
    if created_after:
        q = q.filter(created_date__gte=created_after)
    created_before = parse_date(request.args.get('created_before', ''))
    if created_before:
        q = q.filter(created_date__lte=created_before)

    updated_after = parse_date(request.args.get('updated_after', ''))
    if updated_after:
        q = q.filter(last_update__gte=updated_after)
    updated_before = parse_date(request.args.get('updated_before', ''))
    if updated_before:
        q = q.filter(last_update__lte=updated_before)

    if request.args.get('only_new', '').lower() == 'true':
        q = q.filter(created_date__gte=datetime.now() - timedelta(hours=24))

    has_http = request.args.get('has_http', '').lower()
    if has_http in ('true', 'false'):
        http_subs = set(Http.objects().distinct('subdomain'))
        if has_http == 'true':
            q = q.filter(subdomain__in=http_subs)
        else:
            q = q.filter(subdomain__nin=http_subs)

    sort_map = {
        'created_date': '+created_date', '-created_date': '-created_date',
        'last_update': '+last_update', '-last_update': '-last_update',
        'subdomain': '+subdomain', '-subdomain': '-subdomain',
    }
    order = sort_map.get(request.args.get('sort', '-created_date'), '-created_date')
    q = q.order_by(order)

    return jsonify(paginate_response(q, page, per_page, serialize_live))


# ==========================================
# HTTP Services — Rich Filtering
# ==========================================

@app.route('/api/http', methods=['GET'])
@require_auth
def get_http():
    """
    دریافت HTTP سرویس‌ها با فیلترهای پیشرفته.

    Query Params:
      - program        : نام برنامه
      - programs       : چند برنامه با کاما
      - scope          : دامنه اصلی
      - search         : جستجو در url/subdomain/title
      - status_code    : کد وضعیت دقیق (200)
      - status_codes   : چند کد با کاما (200,301,403)
      - status_range   : محدوده کد (200-299)
      - tech           : نام تکنولوژی خاص (nginx, wordpress, ...)
      - techs          : چند تکنولوژی با کاما
      - title          : جستجو در title
      - ip             : فیلتر بر اساس IP
      - has_favicon    : true/false
      - has_tech       : true/false — آیا تکنولوژی شناسایی شده؟
      - header_key     : بررسی وجود یک header خاص (X-Powered-By)
      - header_value   : مقدار header (با header_key ترکیب می‌شود)
      - tested         : true/false — فیلتر بر اساس وضعیت تست شده یا نشده
      - created_after, created_before
      - updated_after, updated_before
      - only_new       : true — ۲۴ ساعت اخیر
      - only_changed   : true — آپدیت شده در ۲۴ ساعت اخیر
      - sort           : created_date / last_update / status_code / title
      - page, per_page
    """
    page, per_page = get_pagination_args()
    q = Http.objects()

    program = request.args.get('program', '').strip()
    programs_csv = request.args.get('programs', '').strip()
    if program:
        q = q.filter(program_name=program)
    elif programs_csv:
        q = q.filter(program_name__in=[p.strip() for p in programs_csv.split(',') if p.strip()])

    scope = request.args.get('scope', '').strip()
    if scope:
        q = q.filter(scope=scope)

    # جستجوی عمومی در url، title و subdomain
    search = request.args.get('search', '').strip()
    if search:
        q = q.filter(
            Q(subdomain__icontains=search) |
            Q(url__icontains=search) |
            Q(title__icontains=search)
        )

    # فیلتر status code
# === فیلتر Status Code (هوشمند) ===
    status_query = request.args.get('status_code', '').strip()
    if status_query:
        if '-' in status_query:
            try:
                low, high = map(int, status_query.split('-'))
                q = q.filter(status_code__gte=low, status_code__lte=high)
            except ValueError:
                pass
        elif ',' in status_query:
            codes = [int(c.strip()) for c in status_query.split(',') if c.strip().isdigit()]
            if codes:
                q = q.filter(status_code__in=codes)
        elif status_query.isdigit():
            q = q.filter(status_code=int(status_query))

    # === فیلتر Technology (هوشمند) ===
    tech_query = request.args.get('tech', '').strip()
    if tech_query:
        if ',' in tech_query:
            tech_list = [t.strip() for t in tech_query.split(',') if t.strip()]
            if tech_list:
                q = q.filter(tech__in=tech_list)
        else:
            q = q.filter(tech__icontains=tech_query)

    # جستجو در title
    title = request.args.get('title', '').strip()
    if title:
        q = q.filter(title__icontains=title)

    # فیلتر IP
    ip = request.args.get('ip', '').strip()
    if ip:
        q = q.filter(ips=ip)

    # فیلتر provider (case-insensitive)
    provider = request.args.get('provider', '').strip()
    if provider:
        # جستجوی case-insensitive برای provider
        provider_lower = provider.lower()
        subdomains_with_provider = []
        for sd in Subdomains.objects().only('subdomain', 'providers'):
            if sd.providers and any(p.lower() == provider_lower for p in sd.providers):
                subdomains_with_provider.append(sd.subdomain)
        if subdomains_with_provider:
            q = q.filter(subdomain__in=subdomains_with_provider)
        else:
            # اگر هیچ subdomain پیدا نشد، نتیجه خالی کن
            q = q.filter(subdomain='__NO_MATCH__')

    # فیلتر: فقط آن‌هایی که توسط یک پروایدر یافت شده‌اند
    only_single_provider = request.args.get('only_single_provider', '').lower()
    if only_single_provider == 'true':
        # اگر provider مشخص شده باشد، محدود به همان provider که تنها یافته باشد
        if provider:
            docs = Subdomains.objects(providers=provider).only('subdomain', 'providers')
            single_subs = {sd.subdomain for sd in docs if sd.providers and len(sd.providers) == 1}
        else:
            docs = Subdomains.objects().only('subdomain', 'providers')
            single_subs = {sd.subdomain for sd in docs if sd.providers and len(sd.providers) == 1}

        # اگر هیچ subdomain ای پیدا نشد، نتیجه باید خالی باشد
        if single_subs:
            q = q.filter(subdomain__in=single_subs)
        else:
            # Force empty query by filtering on impossible value
            q = q.filter(subdomain='__NO_MATCH__')

    # فیلتر favicon
    has_favicon = request.args.get('has_favicon', '').lower()
    if has_favicon == 'true':
        q = q.filter(favicon__ne='').filter(favicon__exists=True)
    elif has_favicon == 'false':
        q = q.filter(Q(favicon='') | Q(favicon__exists=False))

    # فیلتر header
    header_key = request.args.get('header_key', '').strip()
    if header_key:
        header_value = request.args.get('header_value', '').strip()
        field = f'headers__{header_key.lower().replace("-", "_")}'
        if header_value:
            q = q.filter(**{field + '__icontains': header_value})
        else:
            q = q.filter(**{field + '__exists': True})

    # فیلتر تست شده (tested) - فقط برای این تابع
    tested = request.args.get('tested', '').lower()
    if tested == 'true':
        q = q.filter(tested=True)
    elif tested == 'false':
        q = q.filter(tested=False)

    # تاریخ‌ها
    created_after = parse_date(request.args.get('created_after', ''))
    if created_after:
        q = q.filter(created_date__gte=created_after)
    created_before = parse_date(request.args.get('created_before', ''))
    if created_before:
        q = q.filter(created_date__lte=created_before)

    updated_after = parse_date(request.args.get('updated_after', ''))
    if updated_after:
        q = q.filter(last_update__gte=updated_after)
    updated_before = parse_date(request.args.get('updated_before', ''))
    if updated_before:
        q = q.filter(last_update__lte=updated_before)

    if request.args.get('only_new', '').lower() == 'true':
        q = q.filter(created_date__gte=datetime.now() - timedelta(hours=24))

    if request.args.get('only_changed', '').lower() == 'true':
        q = q.filter(last_update__gte=datetime.now() - timedelta(hours=24))

    sort_map = {
        'created_date': '+created_date', '-created_date': '-created_date',
        'last_update': '+last_update', '-last_update': '-last_update',
        'status_code': '+status_code', '-status_code': '-status_code',
        'title': '+title', '-title': '-title',
    }
    order = sort_map.get(request.args.get('sort', '-created_date'), '-created_date')
    q = q.order_by(order)

    total = q.count()
    http_objs = list(q.skip((page - 1) * per_page).limit(per_page))
    subdomains = [h.subdomain for h in http_objs]
    provider_docs = Subdomains.objects(subdomain__in=subdomains).only('subdomain', 'providers')
    provider_map = {sd.subdomain: sd.providers for sd in provider_docs}

    return jsonify({
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': (total + per_page - 1) // per_page,
        'data': [serialize_http(h, provider_map.get(h.subdomain, [])) for h in http_objs]
    })
# ==========================================
# Target Testing Management
# ==========================================

@app.route('/api/tested', methods=['POST'])
@require_auth
def set_tested_status():
    """
    تغییر وضعیت تست شده (tested) برای یک تارگت خاص در تمام جداول.
    Body JSON:
    {
      "subdomain": "example.com",
      "tested": true  // یا false
    }
    """
    data = request.get_json()
    if not data or 'subdomain' not in data or 'tested' not in data:
        return jsonify({'error': 'Missing subdomain or tested field'}), 400

    subdomain = data['subdomain']
    tested_status = bool(data['tested'])

    # آپدیت وضعیت در تمام کالکشن‌ها به صورت همزمان (Bulk Update)
    Subdomains.objects(subdomain=subdomain).update(set__tested=tested_status)
    LiveSubdomains.objects(subdomain=subdomain).update(set__tested=tested_status)
    Http.objects(subdomain=subdomain).update(set__tested=tested_status)

    return jsonify({
        'status': 'success',
        'subdomain': subdomain,
        'tested': tested_status,
        'message': f'Status successfully updated to {tested_status} for {subdomain}'
    })


# ==========================================
# Assets — Combined/Joined View
# ==========================================

@app.route('/api/assets', methods=['GET'])
@require_auth
def get_assets():
    """
    دیدگاه ترکیبی: ساب‌دامین + وضعیت live + وضعیت HTTP در یک جواب.
    مناسب برای صفحه اصلی داشبورد.

    Query Params:
      - program        : فیلتر برنامه
      - scope          : فیلتر scope
      - search         : جستجو در subdomain
      - status         : all / live_only / http_only / both / none
      - provider       : پروایدر خاص
      - page, per_page
    """
    page, per_page = get_pagination_args()

    program = request.args.get('program', '').strip()
    scope = request.args.get('scope', '').strip()
    search = request.args.get('search', '').strip()
    status_filter = request.args.get('status', 'all').lower()
    provider = request.args.get('provider', '').strip()

    q = Subdomains.objects()
    if program:
        q = q.filter(program_name=program)
    if scope:
        q = q.filter(scope=scope)
    if search:
        q = q.filter(subdomain__icontains=search)
    if provider:
        q = q.filter(providers=provider)

    total = q.count()
    subs = q.skip((page - 1) * per_page).limit(per_page)

    # ایجاد map سریع برای live و http
    sub_names = [s.subdomain for s in subs]
    live_map = {l.subdomain: l for l in LiveSubdomains.objects(subdomain__in=sub_names)}
    http_map = {h.subdomain: h for h in Http.objects(subdomain__in=sub_names)}

    results = []
    for sd in Subdomains.objects(subdomain__in=sub_names).order_by('-created_date'):
        live_obj = live_map.get(sd.subdomain)
        http_obj = http_map.get(sd.subdomain)

        asset_status = 'none'
        if live_obj and http_obj:
            asset_status = 'both'
        elif live_obj:
            asset_status = 'live_only'
        elif http_obj:
            asset_status = 'http_only'

        if status_filter != 'all' and asset_status != status_filter:
            continue

        entry = {
            'subdomain': sd.subdomain,
            'program_name': sd.program_name,
            'scope': sd.scope,
            'providers': sd.providers,
            'status': asset_status,
            'created_date': sd.created_date.strftime('%Y-%m-%d %H:%M:%S') if sd.created_date else None,
        }
        if live_obj:
            entry['live'] = {
                'ips': live_obj.ips,
                'cdn': live_obj.cdn,
                'last_update': live_obj.last_update.strftime('%Y-%m-%d %H:%M:%S') if live_obj.last_update else None,
            }
        if http_obj:
            entry['http'] = {
                'url': http_obj.url,
                'title': http_obj.title,
                'status_code': http_obj.status_code,
                'tech': http_obj.tech,
                'favicon': http_obj.favicon,
                'last_update': http_obj.last_update.strftime('%Y-%m-%d %H:%M:%S') if http_obj.last_update else None,
            }
        results.append(entry)

    return jsonify({
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': (total + per_page - 1) // per_page,
        'data': results
    })


# ==========================================
# Stats & Aggregations
# ==========================================

@app.route('/api/stats', methods=['GET'])
@require_auth
def global_stats():
    """آمار کلی سیستم"""
    return jsonify({
        'programs': Programs.objects().count(),
        'subdomains': Subdomains.objects().count(),
        'live': LiveSubdomains.objects().count(),
        'http': Http.objects().count(),
        'new_subdomains_24h': Subdomains.objects(
            created_date__gte=datetime.now() - timedelta(hours=24)).count(),
        'new_live_24h': LiveSubdomains.objects(
            created_date__gte=datetime.now() - timedelta(hours=24)).count(),
        'new_http_24h': Http.objects(
            created_date__gte=datetime.now() - timedelta(hours=24)).count(),
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })


@app.route('/api/stats/program/<program_name>', methods=['GET'])
@require_auth
def program_stats(program_name):
    """آمار دقیق یک برنامه"""
    program = Programs.objects(program_name=program_name).first()
    if not program:
        return jsonify({'error': 'Program not found'}), 404

    # توزیع status code
    http_objs = Http.objects(program_name=program_name)
    status_dist = {}
    for h in http_objs:
        key = str(h.status_code)
        status_dist[key] = status_dist.get(key, 0) + 1

    # توزیع CDN
    live_objs = LiveSubdomains.objects(program_name=program_name)
    cdn_dist = {}
    for l in live_objs:
        cdn = l.cdn or 'none'
        cdn_dist[cdn] = cdn_dist.get(cdn, 0) + 1

    # توزیع provider
    subs = Subdomains.objects(program_name=program_name)
    provider_dist = {}
    for s in subs:
        for p in s.providers:
            provider_dist[p] = provider_dist.get(p, 0) + 1

    # توزیع tech
    tech_dist = {}
    for h in http_objs:
        for t in h.tech:
            tech_dist[t] = tech_dist.get(t, 0) + 1

    # top 10 تکنولوژی
    top_techs = sorted(tech_dist.items(), key=lambda x: x[1], reverse=True)[:10]

    return jsonify({
        'program_name': program_name,
        'totals': {
            'subdomains': subs.count(),
            'live': live_objs.count(),
            'http': http_objs.count(),
        },
        'new_24h': {
            'subdomains': Subdomains.objects(
                program_name=program_name,
                created_date__gte=datetime.now() - timedelta(hours=24)).count(),
            'live': LiveSubdomains.objects(
                program_name=program_name,
                created_date__gte=datetime.now() - timedelta(hours=24)).count(),
            'http': Http.objects(
                program_name=program_name,
                created_date__gte=datetime.now() - timedelta(hours=24)).count(),
        },
        'distributions': {
            'status_codes': status_dist,
            'cdn': cdn_dist,
            'providers': provider_dist,
            'top_techs': dict(top_techs),
        }
    })


@app.route('/api/stats/timeline', methods=['GET'])
@require_auth
def timeline_stats():
    """
    آمار روزانه کشف دارایی‌ها در ۳۰ روز گذشته.
    Params:
      - program : اختیاری — محدود به یک برنامه
      - days    : تعداد روز (پیشفرض: 30)
    """
    program = request.args.get('program', '').strip()
    days = request.args.get('days', 30, type=int)
    days = min(days, 90)

    timeline = []
    for i in range(days - 1, -1, -1):
        day_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=i)
        day_end = day_start + timedelta(days=1)

        filters = {'created_date__gte': day_start, 'created_date__lt': day_end}
        if program:
            filters['program_name'] = program

        timeline.append({
            'date': day_start.strftime('%Y-%m-%d'),
            'subdomains': Subdomains.objects(**filters).count(),
            'live': LiveSubdomains.objects(**filters).count(),
            'http': Http.objects(**filters).count(),
        })

    return jsonify({'days': days, 'program': program or 'all', 'data': timeline})


# ==========================================
# Lookup & Meta — برای populate کردن فیلترها در UI
# ==========================================

@app.route('/api/meta/providers', methods=['GET'])
@require_auth
def get_providers():
    """لیست تمام providerهای شناخته شده (برای dropdown فیلتر)"""
    program = request.args.get('program', '').strip()
    q = Subdomains.objects()
    if program:
        q = q.filter(program_name=program)
    all_providers = set()
    for sub in q.only('providers'):
        all_providers.update(sub.providers)
    return jsonify(sorted(all_providers))


@app.route('/api/meta/techs', methods=['GET'])
@require_auth
def get_techs():
    """لیست تمام تکنولوژی‌های شناسایی شده (برای dropdown فیلتر)"""
    program = request.args.get('program', '').strip()
    q = Http.objects()
    if program:
        q = q.filter(program_name=program)
    tech_count = {}
    for h in q.only('tech'):
        for t in h.tech:
            tech_count[t] = tech_count.get(t, 0) + 1
    sorted_techs = sorted(tech_count.items(), key=lambda x: x[1], reverse=True)
    return jsonify([{'name': t, 'count': c} for t, c in sorted_techs])


@app.route('/api/meta/cdns', methods=['GET'])
@require_auth
def get_cdns():
    """لیست CDNهای شناسایی شده"""
    program = request.args.get('program', '').strip()
    q = LiveSubdomains.objects(cdn__ne='')
    if program:
        q = q.filter(program_name=program)
    cdn_count = {}
    for l in q.only('cdn'):
        if l.cdn:
            cdn_count[l.cdn] = cdn_count.get(l.cdn, 0) + 1
    return jsonify([{'name': c, 'count': n} for c, n in sorted(cdn_count.items(), key=lambda x: x[1], reverse=True)])


@app.route('/api/meta/scopes', methods=['GET'])
@require_auth
def get_scopes():
    """لیست scopes برای فیلتر"""
    program = request.args.get('program', '').strip()
    if program:
        p = Programs.objects(program_name=program).first()
        return jsonify(p.scopes if p else [])
    all_scopes = set()
    for p in Programs.objects().only('scopes'):
        all_scopes.update(p.scopes)
    return jsonify(sorted(all_scopes))


@app.route('/api/meta/ips', methods=['GET'])
@require_auth
def get_ips():
    """لیست IP‌های منحصربه‌فرد (با فیلتر برنامه)"""
    program = request.args.get('program', '').strip()
    q = Http.objects()
    if program:
        q = q.filter(program_name=program)
    all_ips = set()
    for h in q.only('ips'):
        all_ips.update(h.ips)
    return jsonify(sorted(all_ips))


# ==========================================
# Search — جستجوی سراسری
# ==========================================

@app.route('/api/search', methods=['GET'])
@require_auth
def global_search():
    """
    جستجوی سراسری در تمام جداول.
    Params:
      - q       : رشته جستجو (الزامی، حداقل ۳ کاراکتر)
      - program : محدود کردن به برنامه خاص
      - limit   : حداکثر تعداد نتیجه از هر دسته (پیشفرض: 10)
    """
    query = request.args.get('q', '').strip()
    program = request.args.get('program', '').strip()
    limit = min(request.args.get('limit', 10, type=int), 50)

    if len(query) < 3:
        return jsonify({'error': 'Query must be at least 3 characters'}), 400

    base_filter = {}
    if program:
        base_filter['program_name'] = program

    subs = Subdomains.objects(subdomain__icontains=query, **base_filter).limit(limit)
    lives = LiveSubdomains.objects(subdomain__icontains=query, **base_filter).limit(limit)
    https = Http.objects(
        Q(subdomain__icontains=query) | Q(url__icontains=query) | Q(title__icontains=query),
        **base_filter
    ).limit(limit)

    return jsonify({
        'query': query,
        'results': {
            'subdomains': [serialize_subdomain(s) for s in subs],
            'live': [serialize_live(l) for l in lives],
            'http': [serialize_http(h) for h in https],
        }
    })


# ==========================================
# Export
# ==========================================

@app.route('/api/export/subdomains', methods=['GET'])
@require_auth
def export_subdomains():
    """
    خروجی plain text از ساب‌دامین‌ها (یک خط یک دامنه).
    همان فیلترهای /api/subdomains را می‌پذیرد.
    مناسب برای pipe کردن مستقیم به ابزارهای ریکان.
    """
    q = Subdomains.objects()
    program = request.args.get('program', '').strip()
    scope = request.args.get('scope', '').strip()
    provider = request.args.get('provider', '').strip()
    has_http = request.args.get('has_http', '').lower()
    has_live = request.args.get('has_live', '').lower()

    if program:
        q = q.filter(program_name=program)
    if scope:
        q = q.filter(scope=scope)
    if provider:
        q = q.filter(providers=provider)

    if has_live in ('true', 'false'):
        live_subs = set(LiveSubdomains.objects().distinct('subdomain'))
        q = q.filter(subdomain__in=live_subs) if has_live == 'true' else q.filter(subdomain__nin=live_subs)

    if has_http in ('true', 'false'):
        http_subs = set(Http.objects().distinct('subdomain'))
        q = q.filter(subdomain__in=http_subs) if has_http == 'true' else q.filter(subdomain__nin=http_subs)

    text = '\n'.join(sd.subdomain for sd in q)
    return app.response_class(text, mimetype='text/plain')


@app.route('/api/export/urls', methods=['GET'])
@require_auth
def export_urls():
    """خروجی plain text از URLها — مستقیم برای ابزارها"""
    q = Http.objects()
    program = request.args.get('program', '').strip()
    scope = request.args.get('scope', '').strip()
    status_code = request.args.get('status_code', type=int)

    if program:
        q = q.filter(program_name=program)
    if scope:
        q = q.filter(scope=scope)
    if status_code:
        q = q.filter(status_code=status_code)

    urls = [h.url or h.subdomain for h in q if h.url or h.subdomain]
    return app.response_class('\n'.join(urls), mimetype='text/plain')

@app.route('/api/export/lives', methods=['GET'])
@require_auth
def export_lives():
    """
    خروجی plain text از ساب‌دامین‌های زنده (یک خط یک دامنه).
    """
    q = LiveSubdomains.objects()
    program = request.args.get('program', '').strip()
    scope = request.args.get('scope', '').strip()
    cdn = request.args.get('cdn', '').strip()
    has_cdn = request.args.get('has_cdn', '').lower()

    if program:
        q = q.filter(program_name=program)
    if scope:
        q = q.filter(scope=scope)
    if cdn:
        q = q.filter(cdn__icontains=cdn)

    if has_cdn == 'true':
        q = q.filter(cdn__ne='').filter(cdn__exists=True)
    elif has_cdn == 'false':
        q = q.filter(Q(cdn='') | Q(cdn__exists=False))

    text = '\n'.join(l.subdomain for l in q)
    return app.response_class(text, mimetype='text/plain')


@app.route('/api/export/lives/ips', methods=['GET'])
@require_auth
def export_lives_ips():
    """
    خروجی plain text از تمام IPهای ساب‌دامین‌های زنده (یک خط یک IP بدون تکرار).
    """
    q = LiveSubdomains.objects()
    program = request.args.get('program', '').strip()
    scope = request.args.get('scope', '').strip()
    cdn = request.args.get('cdn', '').strip()
    has_cdn = request.args.get('has_cdn', '').lower()

    if program:
        q = q.filter(program_name=program)
    if scope:
        q = q.filter(scope=scope)
    if cdn:
        q = q.filter(cdn__icontains=cdn)

    if has_cdn == 'true':
        q = q.filter(cdn__ne='').filter(cdn__exists=True)
    elif has_cdn == 'false':
        q = q.filter(Q(cdn='') | Q(cdn__exists=False))

    # استخراج IPهای یونیک
    unique_ips = set()
    for l in q.only('ips'):
        for ip in l.ips:
            if ip:  # اطمینان از خالی نبودن
                unique_ips.add(ip)

    # مرتب‌سازی IPها و تبدیل به رشته
    text = '\n'.join(sorted(list(unique_ips)))
    return app.response_class(text, mimetype='text/plain')
# ==========================================
# Entry Point
# ==========================================

if __name__ == '__main__':
    def handler(sig, frame):
        print('\n[!] Shutting down Watchtower API cleanly...')
        sys.exit(0)

    signal.signal(signal.SIGINT, handler)
    app.run(host='127.0.0.1', port=3131, debug=False)