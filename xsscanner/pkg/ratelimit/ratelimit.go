package ratelimit

import (
	"bufio"
	"crypto/tls"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	ticker       *time.Ticker
	proxies      []string
	proxyCounter int
	mu           sync.Mutex
)

// StartServer یک Ticker گلوبال می‌سازد تا سرعت درخواست‌ها کنترل شود.
// الان روی ۵ درخواست در ثانیه (هر ۲۰۰ میلی‌ثانیه) تنظیم شده است.
func StartServer() {
	ticker = time.NewTicker(200 * time.Millisecond)
}

// LoadProxies فایل پروکسی‌ها را می‌خواند و در حافظه ذخیره می‌کند.
func LoadProxies(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		p := strings.TrimSpace(scanner.Text())
		if p != "" {
			// اضافه کردن پروتکل پیش‌فرض در صورت نبود آن
			if !strings.HasPrefix(p, "http") && !strings.HasPrefix(p, "socks") {
				p = "http://" + p
			}
			proxies = append(proxies, p)
		}
	}
	return nil
}

// Acquire قبل از هر درخواست شبکه صدا زده می‌شود و تا زمان مجاز منتظر می‌ماند.
func Acquire(targetURL string) {
	if ticker != nil {
		<-ticker.C
	}
}

// GetHTTPClient یک کلاینت HTTP با تنظیمات تایم‌اوت و پروکسی چرخشی برمی‌گرداند.
func GetHTTPClient(targetURL string) *http.Client {
	transport := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, // عبور از خطاهای SSL
	}

	// اگر لیست پروکسی خالی نبود، به صورت نوبتی (Round-Robin) یکی را انتخاب کن
	if len(proxies) > 0 {
		mu.Lock()
		proxyStr := proxies[proxyCounter%len(proxies)]
		proxyCounter++
		mu.Unlock()

		if proxyURL, err := url.Parse(proxyStr); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second, // جلوگیری از گیر کردن (Deadlock) روی درخواست‌های بی‌پاسخ
	}
}
