import ipaddress
import re
import tldextract

def is_url(scope: str) -> bool:
    """بررسی می‌کند که آیا scope یک URL کامل یا دارای path است."""
    scope_lower = scope.lower()
    if scope_lower.startswith("http://") or scope_lower.startswith("https://"):
        return True
    if "/" in scope:
        return True
    return False

def is_ip_or_cidr(scope: str) -> bool:
    """بررسی می‌کند که آیا scope یک آدرس IP یا رنج CIDR است."""
    try:
        if "/" in scope:
            ipaddress.ip_network(scope, strict=False)
        else:
            ipaddress.ip_address(scope)
        return True
    except ValueError:
        return False

def classify_scope(scope: str) -> str:
    """
    برمی‌گرداند یکی از:
      - "wildcard"        اگر شامل '*' باشد
      - "url"             اگر با http:// یا https:// شروع شود یا شامل '/' باشد
      - "ip_or_cidr"       اگر IP یا CIDR معتبر باشد
      - "literal_subdomain" در غیر این صورت (یک FQDN ساده و مشخص)
    """
    if "*" in scope:
        return "wildcard"
    if is_url(scope):
        return "url"
    if is_ip_or_cidr(scope):
        return "ip_or_cidr"
    
    # بررسی FQDN بودن (حداقل یک نقطه و فقط شامل حروف، اعداد، خط‌تیره و نقطه)
    if "." in scope and re.match(r"^[a-zA-Z0-9.-]+$", scope):
        return "literal_subdomain"
    
    return "unknown"

def is_enumerable_domain(scope: str) -> bool:
    """بررسی می‌کند که آیا scope برای عملیات enum (subfinder/crtsh/wayback) مناسب است یا خیر."""
    classification = classify_scope(scope)
    
    if classification in ("url", "ip_or_cidr"):
        return False
        
    if classification == "literal_subdomain":
        # اگر فقط یک دامنه‌ی ریشه باشد (مثلاً cbre.com) باید enum شود.
        # اما اگر ساب‌دامین عمیق باشد (مثلاً aac01.mydevices.cbre.com) نباید enum شود.
        ext = tldextract.extract(scope)
        root_domain = f"{ext.domain}.{ext.suffix}"
        if scope == root_domain:
            return True
        return False
        
    return True