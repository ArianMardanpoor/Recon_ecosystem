#!/usr/bin/env python3
"""
Watchtower API - Full-Featured Recon Dashboard Backend
Supports rich multi-field filtering across all asset types
"""
import os
import re
from flask import Flask, request, jsonify
from datetime import datetime, timedelta
import signal
import sys
from mongoengine.queryset.visitor import Q
from database.db import (
    Programs, Subdomains, LiveSubdomains, Http,
    current_time
)

app = Flask(__name__)

# ==========================================
# Helpers
# ==========================================

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
    """Convert date string to datetime - Format: YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS"""
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
        'tested': getattr(sd, 'tested', False),
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
        'tested': getattr(l, 'tested', False),
        'created_date': l.created_date.strftime('%Y-%m-%d %H:%M:%S') if l.created_date else None,
        'last_update': l.last_update.strftime('%Y-%m-%d %H:%M:%S') if l.last_update else None
    }


def serialize_http(h, providers=None):
    findings_list = getattr(h, 'findings', [])
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
        'tested': getattr(h, 'tested', False),
        'providers': providers or [],
        # New scan artifact fields
        'passive_urls': getattr(h, 'passive_urls', []),
        'crawled_urls': getattr(h, 'crawled_urls', []),
        'discovered_params': getattr(h, 'discovered_params', []),
        'scan_status': getattr(h, 'scan_status', 'not_scanned'),
        'last_scan_date': h.last_scan_date.strftime('%Y-%m-%d %H:%M:%S') if getattr(h, 'last_scan_date', None) else None,
        'findings_count': len(findings_list),
        'findings_summary': [
            {
                'parameter': f.get('parameter'),
                'confidence': f.get('confidence'),
                'discovery_source': f.get('discovery_source')
            } for f in findings_list
        ],
        'created_date': h.created_date.strftime('%Y-%m-%d %H:%M:%S') if h.created_date else None,
        'last_update': h.last_update.strftime('%Y-%m-%d %H:%M:%S') if h.last_update else None
    }


def serialize_http_detail(h, providers=None):
    base_data = serialize_http(h, providers)
    # Remove summary and replace with full findings payload
    base_data.pop('findings_summary', None)
    
    # Safe list conversion for BaseList to avoid jsonify crash
    raw_findings = getattr(h, 'findings', [])
    base_data['findings'] = [dict(f) for f in raw_findings]
    
    return base_data


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
def get_programs():
    """
    List programs with filters.
    Params:
      - search: Search in program name
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
def get_program(program_name):
    """Specific program details with statistics"""
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
def get_subdomains():
    """
    Get subdomains with advanced filtering.

    Query Params:
      - program       : Exact program name
      - programs      : Comma-separated programs
      - scope         : Root domain scope
      - provider      : Exact provider name
      - providers     : Comma-separated providers
      - search        : Search substring in subdomain
      - has_http      : true/false — Exists in http table?
      - has_live      : true/false — Exists in live table?
      - created_after : YYYY-MM-DD
      - created_before: YYYY-MM-DD
      - updated_after : YYYY-MM-DD
      - updated_before: YYYY-MM-DD
      - only_new      : true — Created in last 24h
      - sort          : created_date / last_update / subdomain
      - page, per_page
    """
    page, per_page = get_pagination_args()
    q = Subdomains.objects()

    # Program Filter
    program = request.args.get('program', '').strip()
    programs_csv = request.args.get('programs', '').strip()
    if program:
        q = q.filter(program_name=program)
    elif programs_csv:
        prog_list = [p.strip() for p in programs_csv.split(',') if p.strip()]
        q = q.filter(program_name__in=prog_list)

    # Scope Filter
    scope = request.args.get('scope', '').strip()
    if scope:
        q = q.filter(scope=scope)

    # Provider Filter
    provider = request.args.get('provider', '').strip()
    providers_csv = request.args.get('providers', '').strip()
    if provider:
        q = q.filter(providers=provider)
    elif providers_csv:
        prov_list = [p.strip() for p in providers_csv.split(',') if p.strip()]
        q = q.filter(providers__in=prov_list)

    # Search Name
    search = request.args.get('search', '').strip()
    if search:
        q = q.filter(subdomain__icontains=search)

    # Creation Date Filter
    created_after = parse_date(request.args.get('created_after', ''))
    if created_after:
        q = q.filter(created_date__gte=created_after)
    created_before = parse_date(request.args.get('created_before', ''))
    if created_before:
        q = q.filter(created_date__lte=created_before)

    # Update Date Filter
    updated_after = parse_date(request.args.get('updated_after', ''))
    if updated_after:
        q = q.filter(last_update__gte=updated_after)
    updated_before = parse_date(request.args.get('updated_before', ''))
    if updated_before:
        q = q.filter(last_update__lte=updated_before)

    # Only New Filter (Last 24h)
    if request.args.get('only_new', '').lower() == 'true':
        q = q.filter(created_date__gte=datetime.now() - timedelta(hours=24))

    # Live / HTTP relation filters via distinct fetch
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

    # Sorting
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

@app.route('/api/lives', methods=['GET'])
def get_lives():
    """
    Get live subdomains with advanced filtering.
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
def get_http():
    """
    Get HTTP services with advanced filtering.

    Query Params:
      - program        : Program name
      - programs       : Comma-separated programs
      - scope          : Root domain scope
      - search         : Search in url/subdomain/title
      - status_code    : Exact status code (200)
      - status_codes   : Comma-separated codes (200,301,403)
      - status_range   : Code range (200-299)
      - tech           : Specific technology (nginx, wordpress)
      - techs          : Comma-separated tech names
      - title          : Search in title
      - ip             : Filter by IP
      - has_favicon    : true/false
      - has_tech       : true/false — Is technology identified?
      - header_key     : Check existence of a specific header (e.g. Server)
      - header_value   : Header value (combined with header_key)
      - tested         : true/false
      - scan_status    : Status of the scan (not_scanned / clean / findings / confirmed_vuln)
      - scan_statuses  : Comma-separated scan statuses
      - has_findings   : true/false — Does it have findings?
      - min_confidence : HIGH/MEDIUM/LOW — Minimum confidence level of findings
      - scanned_after, scanned_before : Scan date filtering
      - created_after, created_before
      - updated_after, updated_before
      - only_new       : true — Last 24 hours
      - only_changed   : true — Updated in last 24 hours
      - sort           : created_date / last_update / status_code / title / scan_status / last_scan_date
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

    # General search in url, title, and subdomain
    search = request.args.get('search', '').strip()
    if search:
        q = q.filter(
            Q(subdomain__icontains=search) |
            Q(url__icontains=search) |
            Q(title__icontains=search)
        )

    # === Status Code Filter (Smart Range/List Parser) ===
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

    # === Technology Filter ===
    tech_query = request.args.get('tech', '').strip()
    if tech_query:
        if ',' in tech_query:
            tech_list = [t.strip() for t in tech_query.split(',') if t.strip()]
            if tech_list:
                q = q.filter(tech__in=tech_list)
        else:
            q = q.filter(tech__icontains=tech_query)

    # Title search
    title = request.args.get('title', '').strip()
    if title:
        q = q.filter(title__icontains=title)

    # IP Filter
    ip = request.args.get('ip', '').strip()
    if ip:
        q = q.filter(ips=ip)

    # Has Tech Filter
    has_tech = request.args.get('has_tech', '').lower()
    if has_tech == 'true':
        q = q.filter(tech__0__exists=True)
    elif has_tech == 'false':
        q = q.filter(Q(tech__exists=False) | Q(tech__size=0))

    # Provider Filter (Case-insensitive)
    provider = request.args.get('provider', '').strip()
    if provider:
        provider_lower = provider.lower()
        subdomains_with_provider = []
        for sd in Subdomains.objects().only('subdomain', 'providers'):
            if sd.providers and any(p.lower() == provider_lower for p in sd.providers):
                subdomains_with_provider.append(sd.subdomain)
        if subdomains_with_provider:
            q = q.filter(subdomain__in=subdomains_with_provider)
        else:
            q = q.filter(subdomain='__NO_MATCH__')

    # Filter: Found only by a single provider
    only_single_provider = request.args.get('only_single_provider', '').lower()
    if only_single_provider == 'true':
        if provider:
            docs = Subdomains.objects(providers=provider).only('subdomain', 'providers')
            single_subs = {sd.subdomain for sd in docs if sd.providers and len(sd.providers) == 1}
        else:
            docs = Subdomains.objects().only('subdomain', 'providers')
            single_subs = {sd.subdomain for sd in docs if sd.providers and len(sd.providers) == 1}

        if single_subs:
            q = q.filter(subdomain__in=single_subs)
        else:
            q = q.filter(subdomain='__NO_MATCH__')

    # Favicon Filter
    has_favicon = request.args.get('has_favicon', '').lower()
    if has_favicon == 'true':
        q = q.filter(favicon__ne='').filter(favicon__exists=True)
    elif has_favicon == 'false':
        q = q.filter(Q(favicon='') | Q(favicon__exists=False))

    # Headers Filter
    header_key = request.args.get('header_key', '').strip()
    if header_key:
        header_value = request.args.get('header_value', '').strip()
        field = f'headers__{header_key.lower().replace("-", "_")}'
        if header_value:
            q = q.filter(**{field + '__icontains': header_value})
        else:
            q = q.filter(**{field + '__exists': True})

    # Tested Status Filter
    tested = request.args.get('tested', '').lower()
    if tested == 'true':
        q = q.filter(tested=True)
    elif tested == 'false':
        q = q.filter(tested=False)

    # === Scan Artifacts Filters ===
    scan_status = request.args.get('scan_status', '').strip()
    if scan_status:
        q = q.filter(scan_status=scan_status)

    scan_statuses = request.args.get('scan_statuses', '').strip()
    if scan_statuses:
        q = q.filter(scan_status__in=[s.strip() for s in scan_statuses.split(',') if s.strip()])

    has_findings = request.args.get('has_findings', '').lower()
    if has_findings == 'true':
        q = q.filter(findings__0__exists=True)
    elif has_findings == 'false':
        q = q.filter(Q(findings__0__exists=False) | Q(findings__exists=False) | Q(findings__size=0))

    min_confidence = request.args.get('min_confidence', '').upper()
    if min_confidence:
        if min_confidence == 'HIGH':
            q = q.filter(findings__confidence__in=['HIGH', 'high'])
        elif min_confidence == 'MEDIUM':
            q = q.filter(findings__confidence__in=['HIGH', 'high', 'MEDIUM', 'medium'])
        elif min_confidence == 'LOW':
            q = q.filter(findings__confidence__in=['HIGH', 'high', 'MEDIUM', 'medium', 'LOW', 'low'])

    # Date Filters
    scanned_after = parse_date(request.args.get('scanned_after', ''))
    if scanned_after:
        q = q.filter(last_scan_date__gte=scanned_after)
    scanned_before = parse_date(request.args.get('scanned_before', ''))
    if scanned_before:
        q = q.filter(last_scan_date__lte=scanned_before)

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
        'scan_status': '+scan_status', '-scan_status': '-scan_status',
        'last_scan_date': '+last_scan_date', '-last_scan_date': '-last_scan_date',
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


@app.route('/api/http/<subdomain>', methods=['GET'])
def get_http_detail(subdomain):
    """Full details of an HTTP service including findings array and context"""
    h = Http.objects(subdomain=subdomain).first()
    if not h:
        return jsonify({'error': 'Not found'}), 404
        
    provider_doc = Subdomains.objects(subdomain=subdomain).only('providers').first()
    providers = provider_doc.providers if provider_doc else []
    
    return jsonify(serialize_http_detail(h, providers))


# ==========================================
# Target Testing Management
# ==========================================

@app.route('/api/tested', methods=['POST'])
def set_tested_status():
    """
    Toggle 'tested' status across all related collections.
    Body JSON format:
    {
      "subdomain": "example.com",
      "tested": true  // or false
    }
    """
    data = request.get_json()
    if not data or 'subdomain' not in data or 'tested' not in data:
        return jsonify({'error': 'Missing subdomain or tested field'}), 400

    subdomain = data['subdomain']
    tested_status = bool(data['tested'])

    # Synchronized Bulk Update across all collections
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
def get_assets():
    """
    Combined view: Subdomain + Live + HTTP data in one payload.
    Ideal for master dashboard feeds.
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

    # Fast mapping references
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
def global_stats():
    """Global system statistics overview"""
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
def program_stats(program_name):
    """Detailed statistics for a specific program"""
    program = Programs.objects(program_name=program_name).first()
    if not program:
        return jsonify({'error': 'Program not found'}), 404

    # Status Code Distribution
    http_objs = Http.objects(program_name=program_name)
    status_dist = {}
    for h in http_objs:
        key = str(h.status_code)
        status_dist[key] = status_dist.get(key, 0) + 1

    # CDN Distribution
    live_objs = LiveSubdomains.objects(program_name=program_name)
    cdn_dist = {}
    for l in live_objs:
        cdn = l.cdn or 'none'
        cdn_dist[cdn] = cdn_dist.get(cdn, 0) + 1

    # Provider Distribution
    subs = Subdomains.objects(program_name=program_name)
    provider_dist = {}
    for s in subs:
        for p in s.providers:
            provider_dist[p] = provider_dist.get(p, 0) + 1

    # Technology Distribution
    tech_dist = {}
    for h in http_objs:
        for t in h.tech:
            tech_dist[t] = tech_dist.get(t, 0) + 1

    # Top 10 Technologies
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
def timeline_stats():
    """
    Daily asset discovery statistics for the last N days.
    Params:
      - program : Optional — restrict to a specific program
      - days    : Lookback period in days (default: 30)
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


@app.route('/api/meta/scan-stats', methods=['GET'])
def get_scan_stats():
    """
    Scan status and findings statistics overview.
    Params:
      - program : Optional — restrict to a specific program
    """
    program = request.args.get('program', '').strip()
    q = Http.objects()
    if program:
        q = q.filter(program_name=program)

    return jsonify({
        'not_scanned': q.filter(scan_status='not_scanned').count(),
        'clean': q.filter(scan_status='clean').count(),
        'findings': q.filter(scan_status='findings').count(),
        'confirmed_vuln': q.filter(scan_status='confirmed_vuln').count(),
        'total': q.count()
    })


# ==========================================
# Lookup & Meta — Data Population for UI dropdowns
# ==========================================

@app.route('/api/meta/providers', methods=['GET'])
def get_providers():
    """List of all known providers"""
    program = request.args.get('program', '').strip()
    q = Subdomains.objects()
    if program:
        q = q.filter(program_name=program)
    all_providers = set()
    for sub in q.only('providers'):
        all_providers.update(sub.providers)
    return jsonify(sorted(all_providers))


@app.route('/api/meta/techs', methods=['GET'])
def get_techs():
    """List of all identified technologies (ranked)"""
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
def get_cdns():
    """List of identified CDNs (ranked)"""
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
def get_scopes():
    """List of scopes"""
    program = request.args.get('program', '').strip()
    if program:
        p = Programs.objects(program_name=program).first()
        return jsonify(p.scopes if p else [])
    all_scopes = set()
    for p in Programs.objects().only('scopes'):
        all_scopes.update(p.scopes)
    return jsonify(sorted(all_scopes))


@app.route('/api/meta/ips', methods=['GET'])
def get_ips():
    """List of unique IP addresses"""
    program = request.args.get('program', '').strip()
    q = Http.objects()
    if program:
        q = q.filter(program_name=program)
    all_ips = set()
    for h in q.only('ips'):
        all_ips.update(h.ips)
    return jsonify(sorted(all_ips))


# ==========================================
# Search — Global Search Aggregation
# ==========================================

@app.route('/api/search', methods=['GET'])
def global_search():
    """
    Cross-collection global search.
    Params:
      - q       : Query string (required, min 3 chars)
      - program : Filter by program scope
      - limit   : Result cap per collection (default: 10)
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
# Export Endpoints
# ==========================================

@app.route('/api/export/subdomains', methods=['GET'])
def export_subdomains():
    """
    Export plain text subdomains (1 per line).
    Useful for piping directly to standard recon tooling.
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
def export_urls():
    """Export plain text URLs directly for HTTP vulnerability scanners"""
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
def export_lives():
    """Export plain text live subdomains (1 per line)"""
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
def export_lives_ips():
    """Export plain text list of all unique IP addresses mapped to live assets"""
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

    # Extract unique IPs
    unique_ips = set()
    for l in q.only('ips'):
        for ip in l.ips:
            if ip:
                unique_ips.add(ip)

    text = '\n'.join(sorted(list(unique_ips)))
    return app.response_class(text, mimetype='text/plain')


@app.route('/api/export/findings', methods=['GET'])
def export_findings():
    """
    Export all findings flattened into a JSON payload.
    Query Params:
      - program        : Program Name
      - scope          : Root domain
      - min_confidence : HIGH/MEDIUM/LOW
      - page, per_page : Applied to the flattened list of findings
    """
    program = request.args.get('program', '').strip()
    scope = request.args.get('scope', '').strip()
    min_confidence = request.args.get('min_confidence', '').upper()
    page, per_page = get_pagination_args()

    q = Http.objects(findings__0__exists=True)
    if program:
        q = q.filter(program_name=program)
    if scope:
        q = q.filter(scope=scope)

    conf_levels = []
    if min_confidence == 'HIGH':
        conf_levels = ['HIGH']
    elif min_confidence == 'MEDIUM':
        conf_levels = ['HIGH', 'MEDIUM']
    elif min_confidence == 'LOW':
        conf_levels = ['HIGH', 'MEDIUM', 'LOW']

    if conf_levels:
        q = q.filter(findings__confidence__in=[c.lower() for c in conf_levels] + conf_levels)

    all_findings = []
    for h in q:
        for f in h.findings:
            conf = str(f.get('confidence', '')).upper()
            if conf_levels and conf not in conf_levels:
                continue
            all_findings.append({
                'subdomain': h.subdomain,
                'url': h.url,
                'program_name': h.program_name,
                'finding': f
            })

    # Flattened Pagination
    total = len(all_findings)
    start = (page - 1) * per_page
    end = start + per_page
    paginated_findings = all_findings[start:end]

    return jsonify({
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': (total + per_page - 1) // per_page,
        'data': paginated_findings
    })


# ==========================================
# Entry Point
# ==========================================

if __name__ == '__main__':
    def handler(sig, frame):
        print('\n[!] Shutting down Watchtower API cleanly...')
        sys.exit(0)

    signal.signal(signal.SIGINT, handler)
    
    # NOTE FOR PRODUCTION:
    # Flask dev server is strictly for local debugging. 
    # In production, run this app using Gunicorn:
    # gunicorn -w 4 -b 127.0.0.1:3131 --timeout 120 app:app
    app.run(host='0.0.0.0', port=3131, debug=False)
    