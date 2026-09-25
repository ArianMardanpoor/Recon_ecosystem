package ratelimit

import (
	"bufio"
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// Config holds rate limit and proxy health-check configurations
type Config struct {
	ReqPerSec           float64
	HealthCheckInterval time.Duration
	HealthCheckTimeout  time.Duration
}

var (
	cfg Config

	// Per-host rate limiters
	limiters   = make(map[string]*rate.Limiter)
	limitersMu sync.Mutex

	// Proxy management
	allProxies    []string
	activeProxies []string
	proxyMu       sync.RWMutex
	proxyCounter  uint64

	hcOnce sync.Once
)

// Init initializes the rate limiter and proxy checker with the given configuration.
func Init(config Config) {
	cfg = config
	if cfg.ReqPerSec <= 0 {
		cfg.ReqPerSec = 1.0 // default to 1 req/s
	}
	if cfg.HealthCheckInterval <= 0 {
		cfg.HealthCheckInterval = 5 * time.Minute
	}
	if cfg.HealthCheckTimeout <= 0 {
		cfg.HealthCheckTimeout = 5 * time.Second
	}
}

// StartServer is kept for backward compatibility. Use Init() instead for full control.
func StartServer() {
	Init(Config{
		ReqPerSec:           1.0,
		HealthCheckInterval: 5 * time.Minute,
		HealthCheckTimeout:  5 * time.Second,
	})
}

// LoadProxies reads proxies from a file and starts the background health check loop.
func LoadProxies(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	var loaded []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		p := strings.TrimSpace(scanner.Text())
		if p != "" {
			if !strings.HasPrefix(p, "http") && !strings.HasPrefix(p, "socks") {
				p = "http://" + p
			}
			loaded = append(loaded, p)
		}
	}

	proxyMu.Lock()
	allProxies = loaded
	activeProxies = append([]string(nil), loaded...)
	proxyMu.Unlock()

	// Start the background health checker only once
	hcOnce.Do(func() {
		if len(allProxies) > 0 {
			go healthCheckLoop()
		}
	})

	return nil
}

// getHost extracts the hostname from the target URL.
func getHost(targetURL string) string {
	u, err := url.Parse(targetURL)
	if err != nil || u.Host == "" {
		return "global_fallback"
	}
	return u.Host
}

// getLimiter retrieves or creates a rate limiter for a specific host.
func getLimiter(host string) *rate.Limiter {
	limitersMu.Lock()
	defer limitersMu.Unlock()

	limiter, exists := limiters[host]
	if !exists {
		// Burst set to 1 strictly enforces the per-request spacing
		limiter = rate.NewLimiter(rate.Limit(cfg.ReqPerSec), 1)
		limiters[host] = limiter
	}
	return limiter
}

// Acquire waits until a request is allowed for the given target URL.
func Acquire(targetURL string) {
	host := getHost(targetURL)
	limiter := getLimiter(host)

	// Wait blocks until the limiter permits the event.
	_ = limiter.Wait(context.Background())
}

// GetHTTPClient returns a thread-safe HTTP client with an active, round-robin proxy.
func GetHTTPClient(targetURL string) *http.Client {
	transport := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}

	proxyMu.RLock()
	activeCount := len(activeProxies)
	var proxyStr string
	if activeCount > 0 {
		idx := atomic.AddUint64(&proxyCounter, 1)
		proxyStr = activeProxies[idx%uint64(activeCount)]
	}
	proxyMu.RUnlock()

	if proxyStr != "" {
		if proxyURL, err := url.Parse(proxyStr); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}
}

// healthCheckLoop periodically checks proxy alive status.
func healthCheckLoop() {
	ticker := time.NewTicker(cfg.HealthCheckInterval)
	defer ticker.Stop()

	// Initial check immediately on load
	checkProxies()

	for range ticker.C {
		checkProxies()
	}
}

// checkProxies pings all known proxies concurrently and updates the active list.
func checkProxies() {
	proxyMu.RLock()
	proxiesToCheck := append([]string(nil), allProxies...)
	proxyMu.RUnlock()

	if len(proxiesToCheck) == 0 {
		return
	}

	var wg sync.WaitGroup
	var aliveMu sync.Mutex
	var aliveProxies []string

	for _, p := range proxiesToCheck {
		wg.Add(1)
		go func(proxy string) {
			defer wg.Done()
			if isProxyAlive(proxy) {
				aliveMu.Lock()
				aliveProxies = append(aliveProxies, proxy)
				aliveMu.Unlock()
			}
		}(p)
	}
	wg.Wait()

	// Update the active list without data races
	proxyMu.Lock()
	activeProxies = aliveProxies
	proxyMu.Unlock()
}

// isProxyAlive performs a HEAD request via the proxy to determine availability.
func isProxyAlive(proxyStr string) bool {
	proxyURL, err := url.Parse(proxyStr)
	if err != nil {
		return false
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true, // Ensure clean connections for testing
		},
		Timeout: cfg.HealthCheckTimeout,
	}

	// Quick HEAD check against a reliable target
	req, err := http.NewRequest("HEAD", "https://httpbin.org/ip", nil)
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode >= 200 && resp.StatusCode < 500
}
