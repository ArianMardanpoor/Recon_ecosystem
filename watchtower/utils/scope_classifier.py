# مسیر فایل: watchtower/utils/scope_classifier.py
import ipaddress

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

def is_enumerable_domain(scope: str) -> bool:
    """بررسی می‌کند که آیا scope برای عملیات enum (subfinder/crtsh/wayback) مناسب است یا خیر."""
    if is_url(scope):
        return False
    if is_ip_or_cidr(scope):
        return False
    return True