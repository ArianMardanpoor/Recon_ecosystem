import requests
import subprocess
import os
import json
import sys
import re
import time

# --- تنظیمات سیستم شما ---
# آدرس پایه API (بدون /api/http چون در تابع اضافه می‌شود)
BASE_API_URL = "http://YOUR_WATCHTOWER_API/api" 
API_TOKEN = "a21uc0lzeTcK"                      # توکن پیش‌فرض در app.py
OLD_TARGETS_FILE = "all_scanned_targets.txt"    # فایل تاریخچه برای anew
OUTPUT_DIR = "./watchtower_scans"               # محل ذخیره لاگ‌های اسکن
XSSNIPER_CMD = "go run xssniper_v2.go -w 5"        # دستور اجرای اسکنر

def log(msg, color="\033[36m"):
    ts = time.strftime("%H:%M:%S")
    print(f"\033[90m[{ts}]\033[0m {color}[BRIDGE] {msg}\033[0m")

def get_data_from_api():
    """دریافت داده‌ها از API واچ‌تاور با مدیریت احراز هویت و صفحه‌بندی"""
    endpoint = f"{BASE_API_URL}/http"
    log(f"Connecting to API: {endpoint}...")
    
    headers = {
        'X-API-Token': "a21uc0lzeTcK"
    }
    
    all_urls = []
    page = 1
    per_page = 100 # مقدار پیش‌فرض در app.py
    
    try:
        while True:
            # استفاده از پارامترهای صفحه‌بندی
            params = {
                'page': page, 
                'per_page': per_page,
                # 'only_new': 'true' # اختیاری: اگر فقط موارد ۲۴ ساعت اخیر را می‌خواهید
            }
            
            response = requests.get(endpoint, headers=headers, params=params, timeout=60)
            response.raise_for_status()
            result = response.json()
            
            # در app.py خروجی به صورت {'data': [...], 'total': x, 'pages': y, ...} است
            if 'data' in result and isinstance(result['data'], list):
                page_data = result['data']
                # استخراج فیلد url از هر آبجکت در لیست data
                page_urls = [item['url'] for item in page_data if 'url' in item]
                all_urls.extend(page_urls)
                
                total_pages = result.get('pages', 1)
                log(f"Fetched page {page}/{total_pages} ({len(page_urls)} items)")
                
                if page < total_pages:
                    page += 1
                else:
                    break
            else:
                log("Unexpected API response format.", "\033[33m")
                break
                
        log(f"Total URLs fetched: {len(all_urls)}")
        return all_urls
    except Exception as e:
        log(f"API Error: {e}", "\033[31m")
        return []

def run_smart_diff(targets):
    """استفاده از anew برای پیدا کردن موارد جدید"""
    log("Running smart diffing with 'anew'...")
    temp_file = "temp_api_targets.txt"
    with open(temp_file, "w") as f:
        f.write("\n".join(targets))
    
    try:
        # anew فقط خطوطی که در OLD_TARGETS_FILE نیستند را برمی‌گرداند و به آن اضافه می‌کند
        cmd = f"cat {temp_file} | anew {OLD_TARGETS_FILE}"
        new_targets = subprocess.check_output(cmd, shell=True).decode().splitlines()
        if os.path.exists(temp_file):
            os.remove(temp_file)
        return [t.strip() for t in new_targets if t.strip()]
    except Exception as e:
        log(f"Diffing Error: {e}", "\033[31m")
        return targets # در صورت خطا، همه را برمی‌گردانیم

def prioritize(targets):
    """اولویت‌بندی بر اساس حساسیت و تکنولوژی"""
    log("Prioritizing targets (PHP, ASP, Login, Search)...")
    high_priority = []
    normal_priority = []
    
    # کلمات کلیدی برای صفحات مستعد باگ
    critical_keywords = [
        "login", "search", "query", "signup", "profile", "edit", "user", 
        "callback", "redirect", "api", "v1", "v2", ".php", ".asp", ".aspx"
    ]
    
    for t in targets:
        if any(k in t.lower() for k in critical_keywords):
            high_priority.append(t)
        else:
            normal_priority.append(t)
            
    log(f"Priority: {len(high_priority)} high, {len(normal_priority)} normal.")
    return high_priority + normal_priority

def get_history_data(url):
    """استفاده از Wayback/GAU برای استخراج پارامترهای قدیمی (Passive)"""
    log(f"Extracting history (Wayback) for {url}...")
    try:
        # استفاده از waybackurls و فیلتر کردن با uro برای حذف تکراری‌ها
        cmd = f"waybackurls {url} | uro | grep '?'"
        history = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().splitlines()
        return list(set(history))
    except:
        return []

def scan_js_for_params(url):
    """پیدا کردن پارامترهای مخفی در فایل‌های جاوااسکریپت"""
    log(f"Monitoring JS files for {url}...")
    try:
        # پیدا کردن فایل‌های JS با Katana
        cmd = f"katana -u {url} -em js -silent"
        js_files = subprocess.check_output(cmd, shell=True).decode().splitlines()
        
        # اینجا می‌توانید از LinkFinder یا Regex ساده برای استخراج پارامتر استفاده کنید
        # فعلاً به Katana تکیه می‌کنیم که پارامترها را هم در خروجی می‌آورد
        return js_files
    except:
        return []

def main():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    # ۱. دریافت داده
    raw_targets = get_data_from_api()
    if not raw_targets:
        log("No data received from API.", "\033[33m")
        return

    # ۲. فیلتر کردن (فقط جدیدها)
    new_targets = run_smart_diff(raw_targets)
    if not new_targets:
        log("No NEW targets found since last scan.", "\033[32m")
        return

    log(f"Ready to process {len(new_targets)} new targets.")

    # ۳. اولویت‌بندی
    final_queue = prioritize(new_targets)

    for target in final_queue:
        log(f"--- Processing: {target} ---", "\033[1m\033[35m")
        
        # ۴. غنی‌سازی با تاریخچه (Wayback)
        history = get_history_data(target)
        
        # ۵. مانیتورینگ JS
        js_links = scan_js_for_params(target)
        
        # ۶. ترکیب همه ورودی‌ها برای اسکنر اصلی
        scan_input_file = os.path.join(OUTPUT_DIR, "current_job.txt")
        with open(scan_input_file, "w") as f:
            f.write(target + "\n")
            for h in history: f.write(h + "\n")
            for j in js_links: f.write(j + "\n")
            
        # ۷. اجرای XSSniper v2.1
        log(f"Launching XSSniper on {target}...")
        try:
            subprocess.run(f"{XSSNIPER_CMD} -l {scan_input_file}", shell=True)
        except KeyboardInterrupt:
            log("Scan interrupted by user.", "\033[31m")
            sys.exit(0)
        except Exception as e:
            log(f"Execution Error: {e}", "\033[31m")

    log("All new targets processed successfully!", "\033[1m\033[32m")

if __name__ == "__main__":
    main()
