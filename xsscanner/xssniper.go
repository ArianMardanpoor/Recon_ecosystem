// FILE: xssniper.go — REFACTORED LOGGING, TECH-AWARE ROUTING & JS RISK DETECTION
// Changes:
// - Added WAF Challenge detection without dropping targets
// - Replaced nuclei with curl_reflect_checker for GET and JSON body reflection checks.
// - Added curlCheckerExists detection and appropriate logging.
// - Added helpers: extractReflectedURLsFromCurl, aggregateCurlFindings.
// - Updated Phase 3 probe loop and Phase 4 heavy-attack loop to use curl_reflect_checker.
// - FIX BUG2: Migrated http-request-to-target functions from net/http to curl-exec to avoid JA3 blocks.
// - FIX BUG4: Upgraded Phase 4 GET reflection aggregation in aggregateCurlFindings to confirmed severity.
// - FIX BUG5: Added retry-on-timeout resilience to curlRequest HTTP helper.
// - Added: HTTP Headers parsing via curl -i, CSP extraction, and Severity downgrade (confirmed -> likely) if strict CSP is present.
// - Added: Location-header and open-redirect checking via new curl_reflect_checker "-check-location" mode.
// - ENHANCEMENT: Made WAF Challenge detection gate Phase 4 heavy payload tasks and log candidates safely.

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reconpipeline/pkg/corscheck"
	"reconpipeline/pkg/ratelimit"
	"reconpipeline/pkg/reflectctx"
	"reconpipeline/pkg/reporter"
	"reconpipeline/pkg/spadetect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var repLogger *reporter.Logger

// FIX BUG2: Shared User-Agent constant for curl requests
const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
	"AppleWebKit/537.36 (KHTML, like Gecko) " +
	"Chrome/126.0.0.0 Safari/537.36"

// ── WAF Challenge Detection ──────────────────────────────────────────────────

var wafChallengeDetected int64

func detectWAFChallenge(statusCode int, body []byte) bool {
	limit := 8192
	if len(body) < limit {
		limit = len(body)
	}
	window := bytes.ToLower(body[:limit])

	fingerprints := []string{
		"cf-browser-verification",
		"attention required! | cloudflare",
		"just a moment...",
		"request unsuccessful. incapsula",
		"__cf_chl_",
		"sucuri_cloudproxy_js",
	}

	for _, fp := range fingerprints {
		if bytes.Contains(window, []byte(fp)) {
			return true
		}
	}

	if bytes.Contains(window, []byte("access denied")) && bytes.Contains(window, []byte("akamai")) {
		return true
	}

	return false
}

// ── Curl Request Helper ──────────────────────────────────────────────────────

func curlRequestAttempt(targetURL, method string, headers map[string]string, body string, timeout int) (statusCode int, respHeaders map[string]string, respBody []byte, err error) {
	args := []string{
		"-s",
		"-L",
		"-i", // اضافه شدن فلگ -i برای دریافت هدرهای HTTP
		"--max-time", strconv.Itoa(timeout),
		"-A", userAgent,
		"-w", "\\nHTTPSTATUS:%{http_code}",
	}

	if method == "HEAD" {
		args = append(args, "-I")
	} else if method == "POST" {
		args = append(args, "-X", "POST")
		args = append(args, "-H", "Content-Type: application/json")
		if body != "" {
			args = append(args, "--data-raw", body)
		}
	} else if method != "GET" && method != "" {
		args = append(args, "-X", method)
	}

	args = append(args, "-H", "Cache-Control: no-cache, no-store, must-revalidate")
	args = append(args, "-H", "Pragma: no-cache")

	for k, v := range headers {
		args = append(args, "-H", fmt.Sprintf("%s: %s", k, v))
	}

	args = append(args, targetURL)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout+10)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "curl", args...)
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	stdout, cmdErr := cmd.Output()

	marker := []byte("\nHTTPSTATUS:")
	idx := bytes.LastIndex(stdout, marker)
	if idx < 0 {
		return 0, nil, nil, fmt.Errorf("curl failed or no marker: %v (stderr: %s)", cmdErr, stderrBuf.String())
	}

	statusStr := strings.TrimSpace(string(stdout[idx+len(marker):]))
	statusCode, atoiErr := strconv.Atoi(statusStr)
	if atoiErr != nil {
		return 0, nil, nil, fmt.Errorf("unparseable status %q", statusStr)
	}

	if statusCode == 0 {
		return 0, nil, nil, fmt.Errorf("connection failed (status 000)")
	}

	// پارس کردن هدرها و جدا کردن بادی (با در نظر گرفتن ریدایرکت‌ها)
	rawOutput := stdout[:idx]
	respHeaders = make(map[string]string)
	offset := 0
	for {
		// رد شدن از کاراکترهای خالی ابتدای پاسخ
		for offset < len(rawOutput) && (rawOutput[offset] == '\r' || rawOutput[offset] == '\n') {
			offset++
		}
		if offset >= len(rawOutput) {
			break
		}
		// بررسی شروع بخش هدر HTTP
		if !bytes.HasPrefix(rawOutput[offset:], []byte("HTTP/")) {
			break
		}
		end := bytes.Index(rawOutput[offset:], []byte("\r\n\r\n"))
		if end == -1 {
			break
		}
		block := string(rawOutput[offset : offset+end])
		lines := strings.Split(block, "\n")
		// ریست کردن هدرها در صورت وجود ریدایرکت تا فقط هدرهای پاسخ نهایی باقی بماند
		respHeaders = make(map[string]string)
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if sepIdx := strings.Index(line, ":"); sepIdx > 0 {
				key := strings.ToLower(strings.TrimSpace(line[:sepIdx]))
				val := strings.TrimSpace(line[sepIdx+1:])
				respHeaders[key] = val
			}
		}
		offset += end + 4
	}
	respBody = rawOutput[offset:]

	return statusCode, respHeaders, respBody, nil
}

func curlRequest(targetURL, method string, headers map[string]string, body string, timeout int) (statusCode int, respHeaders map[string]string, respBody []byte, err error) {
	statusCode, respHeaders, respBody, err = curlRequestAttempt(targetURL, method, headers, body, timeout)
	if err != nil || statusCode == 0 {
		return curlRequestAttempt(targetURL, method, headers, body, timeout*2)
	}
	return statusCode, respHeaders, respBody, nil
}

func extractCSP(headers map[string]string) (allowsInline bool, hasCSP bool) {
	cspStr := ""
	for k, v := range headers {
		if k == "content-security-policy" {
			cspStr = v
			hasCSP = true
			break
		}
	}
	if !hasCSP {
		return true, false // اگر CSP ندارد، عملاً inline باز است
	}

	cspLower := strings.ToLower(cspStr)
	if strings.Contains(cspLower, "'unsafe-inline'") {
		return true, true
	}

	return false, true
}

// ── Tech Profile & Classification ───────────────────────────────────────────

type TechProfile struct {
	IsSPA   bool
	Unknown bool
}

func classifyTechProfile(techList []string) TechProfile {
	if len(techList) == 0 || (len(techList) == 1 && techList[0] == "") {
		return TechProfile{Unknown: true}
	}
	spaKeywords := []string{"react", "next.js", "angular", "vue", "svelte"}

	profile := TechProfile{}
	hasSPA := false

	for _, t := range techList {
		tl := strings.ToLower(strings.TrimSpace(t))
		for _, kw := range spaKeywords {
			if strings.Contains(tl, kw) {
				hasSPA = true
			}
		}
	}

	if hasSPA {
		profile.IsSPA = true
	} else {
		profile.Unknown = true
	}
	return profile
}

// ── Client-Side JS Risk Detection ──────────────────────────────────────────

func hasClientSideJSRisk(targetURL string) bool {
	ratelimit.Acquire(targetURL)
	statusCode, _, respBody, err := curlRequest(targetURL, "GET", nil, "", 15)
	if err != nil || statusCode == 0 {
		return true // conservative fallback
	}
	bodyLower := strings.ToLower(string(respBody))
	return strings.Contains(bodyLower, "<script")
}

// ── Telegram Configuration ───────────────────────────────────────────────────

type Telegram struct {
	Token  string
	ChatID string
}

// ── Vulnerability Reporting ──────────────────────────────────────────────────

type Vulnerability struct {
	Name      string   `json:"parameter,omitempty"`
	Payloads  []string `json:"payloads"`
	Severity  string   `json:"severity"`
	Confirmed bool     `json:"confirmed"`
}

type VulnerabilityReport struct {
	URL               string          `json:"url"`
	QueryParameters   []Vulnerability `json:"query_parameters,omitempty"`
	Headers           []Vulnerability `json:"headers,omitempty"`
	JSONBody          []Vulnerability `json:"json_body,omitempty"`
	DOM               []Vulnerability `json:"dom,omitempty"`
	OpenRedirect      []Vulnerability `json:"open_redirect,omitempty"`
	LocationInjection []Vulnerability `json:"location_injection,omitempty"`
}

type DomSinkOutput struct {
	URL   string   `json:"url"`
	Sinks []string `json:"sinks"`
}

func severityToConfidence(sev string) string {
	switch sev {
	case "confirmed":
		return "HIGH"
	case "likely":
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func logReportFindings(report *VulnerabilityReport) {
	if repLogger == nil {
		return
	}
	u, _ := url.Parse(report.URL)
	root := ""
	if u != nil {
		root = extractRootDomain(u.Hostname())
	}

	logGroup := func(vulns []Vulnerability, source, reflType string) {
		for _, v := range vulns {
			conf := severityToConfidence(v.Severity)
			if v.Confirmed {
				conf = "HIGH"
			}
			repLogger.Log(reporter.NewFinding(
				root, report.URL, v.Name, source, conf, reflType,
				reporter.Context{AllowedChars: v.Payloads},
			))
		}
	}

	logGroup(report.QueryParameters, "xssniper", "source_reflection")
	logGroup(report.Headers, "xssniper", "header_injection")
	logGroup(report.JSONBody, "xssniper", "json_body_injection")
	logGroup(report.DOM, "xssniper", "dom_sink_injection")
	logGroup(report.OpenRedirect, "xssniper", "open_redirect")
	logGroup(report.LocationInjection, "xssniper", "location_header_injection")
}

func (r *VulnerabilityReport) HasVulns() bool {
	return len(r.QueryParameters) > 0 || len(r.Headers) > 0 || len(r.JSONBody) > 0 || len(r.DOM) > 0 || len(r.OpenRedirect) > 0 || len(r.LocationInjection) > 0
}

func redactX9(s string) string {
	return reX9.ReplaceAllString(s, "x9")
}

func (r *VulnerabilityReport) processDomJson(domOut DomSinkOutput, phase string) {
	u, err := url.Parse(domOut.URL)
	if err != nil {
		return
	}

	name := "unknown"
	if u.Fragment != "" && strings.Contains(redactX9(u.Fragment), "x9") {
		name = "fragment"
	} else {
		for k, v := range u.Query() {
			val, _ := url.QueryUnescape(strings.Join(v, ""))
			if strings.Contains(redactX9(val), "x9") {
				name = k
				break
			}
		}
	}

	if name == "unknown" {
		return
	}

	if !isInScope(r.URL, domOut.URL) {
		return
	}

	severity := "likely"
	confirmed := false
	note := ""
	if phase == "dom_confirmed" {
		severity = "confirmed"
		confirmed = true

		canary := ""
		if m := reX9.FindString(domOut.URL); m != "" {
			canary = m
		}

		if canary != "" && u.Fragment != "" {
			if !reflectionExists(domOut.URL, "GET", nil, "", canary) {
				severity = "possible"
				confirmed = false
				note = " (Note: No HTTP reflection, possible false positive)"
			}
		}
	}

	found := false
	for i, v := range r.DOM {
		baseName := strings.Split(v.Name, " (Note:")[0]
		if baseName == name {
			for _, sink := range domOut.Sinks {
				exists := false
				for _, p := range v.Payloads {
					if p == sink {
						exists = true
						break
					}
				}
				if !exists {
					r.DOM[i].Payloads = append(r.DOM[i].Payloads, sink)
				}
			}
			if severityWeight(severity) > severityWeight(v.Severity) {
				r.DOM[i].Severity = severity
			}
			if note != "" && !strings.Contains(r.DOM[i].Name, note) {
				r.DOM[i].Name += note
			}
			if confirmed {
				r.DOM[i].Confirmed = true
			}
			found = true
			break
		}
	}

	if !found {
		r.DOM = append(r.DOM, Vulnerability{
			Name:      name + note,
			Severity:  severity,
			Confirmed: confirmed,
			Payloads:  domOut.Sinks,
		})
	}
}

func (r *VulnerabilityReport) aggregateFindings(nucleiOutput string, phase string) {
	if nucleiOutput == "" {
		return
	}

	lines := strings.Split(strings.TrimSpace(nucleiOutput), "\n")

	for _, line := range lines {
		line = stripANSI(strings.TrimSpace(line))
		line = reCleaning.ReplaceAllString(line, "")
		if line == "" {
			continue
		}

		if (phase == "dom" || phase == "dom_confirmed") && strings.HasPrefix(line, "{") {
			var domOut DomSinkOutput
			if err := json.Unmarshal([]byte(line), &domOut); err == nil {
				r.processDomJson(domOut, phase)
				continue
			}
		}

		payload := ""
		if m := rePayload.FindStringSubmatch(line); len(m) > 0 {
			if m[1] != "" {
				payload = m[1]
			} else {
				payload = m[2]
			}
		}

		rawURL := ""
		parts := strings.Fields(line)
		for _, p := range parts {
			if strings.HasPrefix(p, "http") {
				rawURL = strings.Trim(p, "[]")
				break
			}
		}

		if rawURL == "" {
			continue
		}

		if !isInScope(r.URL, rawURL) {
			continue
		}

		decodedURL, _ := url.QueryUnescape(rawURL)
		injection := ""
		targetURL := rawURL
		if strings.Contains(decodedURL, "|") {
			sub := strings.SplitN(decodedURL, "|", 2)
			targetURL = sub[0]
			injection = sub[1]
		}

		name := "unknown"
		targetList := &r.QueryParameters

		switch phase {
		case "header":
			targetList = &r.Headers
			if strings.Contains(injection, ":") {
				name = strings.SplitN(injection, ":", 2)[0]
			}
		case "json":
			targetList = &r.JSONBody
			if strings.HasPrefix(injection, "{") {
				var data map[string]interface{}
				if err := json.Unmarshal([]byte(injection), &data); err == nil {
					for k, v := range data {
						valStr := fmt.Sprintf("%v", v)
						if strings.Contains(redactX9(valStr), "x9") {
							name = k
							break
						}
					}
				}
			}
		case "dom", "dom_confirmed":
			targetList = &r.DOM
			if u, err := url.Parse(rawURL); err == nil {
				if u.Fragment != "" && strings.Contains(redactX9(u.Fragment), "x9") {
					name = "fragment"
				} else {
					for k, v := range u.Query() {
						val, _ := url.QueryUnescape(strings.Join(v, ""))
						if strings.Contains(redactX9(val), "x9") {
							name = k
							break
						}
					}
				}
			}
		default:
			if u, err := url.Parse(decodedURL); err == nil {
				q := u.Query()
				for k, v := range q {
					for _, val := range v {
						if strings.Contains(redactX9(val), "x9") {
							name = k
							goto found
						}
					}
				}
			}
		found:
		}

		if name == "unknown" {
			continue
		}
		if phase == "header" && strings.HasPrefix(injection, "{") {
			continue
		}

		severity := "possible"
		note := ""
		if phase == "get" {
			severity = "likely"
		} else if phase == "dom" {
			severity = "likely"
		} else if phase == "dom_confirmed" {
			severity = "confirmed"
			phase = "dom"

			canary := ""
			if m := reX9.FindString(rawURL); m != "" {
				canary = m
			}
			if canary != "" {
				if !reflectionExists(targetURL, "GET", nil, "", canary) {
					severity = "possible"
					note = " (Note: No HTTP reflection, possible false positive)"
				}
			}
		} else if phase == "header" || phase == "json" {
			canary := ""
			if m := reX9.FindString(injection); m != "" {
				canary = m
			}
			if canary != "" {
				headers := make(map[string]string)
				method := "GET"
				body := ""
				if phase == "header" {
					parts := strings.SplitN(injection, ":", 2)
					headers[parts[0]] = parts[1]
				} else {
					method = "POST"
					body = injection
				}
				if verifyReflection(targetURL, method, headers, body, canary) {
					severity = "likely"
				} else {
					continue
				}
			}
		}

		found := false
		for i, v := range *targetList {
			if v.Name == name {
				if payload != "" {
					exists := false
					for _, p := range v.Payloads {
						if p == payload {
							exists = true
							break
						}
					}
					if !exists {
						(*targetList)[i].Payloads = append((*targetList)[i].Payloads, payload)
					}
				}
				if severityWeight(severity) > severityWeight((*targetList)[i].Severity) {
					(*targetList)[i].Severity = severity
				}
				if note != "" && !strings.Contains((*targetList)[i].Name, note) {
					(*targetList)[i].Name += note
				}
				found = true
				break
			}
		}
		if !found {
			newVuln := Vulnerability{Name: name + note, Severity: severity}
			if payload != "" {
				newVuln.Payloads = []string{payload}
			}
			*targetList = append(*targetList, newVuln)
		}
	}
}

func severityWeight(s string) int {
	switch s {
	case "confirmed":
		return 3
	case "likely":
		return 2
	case "possible":
		return 1
	default:
		return 0
	}
}

func verifyReflection(targetURL, method string, headers map[string]string, body, canary string) bool {
	ratelimit.Acquire(targetURL)
	statusCode, _, respBody, err := curlRequest(targetURL, method, headers, body, 15)
	if err != nil || statusCode == 0 {
		return false
	}
	return strings.Contains(string(respBody), canary)
}

func loadEnv() {
	candidates := []string{".env"}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), ".env"))
	}
	for _, path := range candidates {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
				if os.Getenv(key) == "" {
					os.Setenv(key, val)
				}
			}
		}
		f.Close()
	}
}

func newTelegram() *Telegram {
	token := os.Getenv("TELEGRAM_BOT_TOKEN")
	chatID := os.Getenv("TELEGRAM_CHAT_ID")
	if token == "" || chatID == "" {
		return nil
	}
	return &Telegram{Token: token, ChatID: chatID}
}

func dedupeNucleiFindings(report VulnerabilityReport) string {
	var sb strings.Builder
	renderSection := func(title string, vulns []Vulnerability) {
		if len(vulns) == 0 {
			return
		}
		sb.WriteString(fmt.Sprintf("\n  %s[%s]%s\n", X_cyan, title, X_reset))
		for _, v := range vulns {
			sevColor := X_gray
			switch v.Severity {
			case "confirmed":
				sevColor = X_red + X_bold
			case "likely":
				sevColor = X_yellow
			case "possible":
				sevColor = X_white
			}
			sb.WriteString(fmt.Sprintf("    - %s: %s [%s]%s\n", v.Name, sevColor, v.Severity, X_reset))
			if len(v.Payloads) > 0 {
				sb.WriteString(fmt.Sprintf("      Payloads: %s\n", strings.Join(v.Payloads, ", ")))
			}
		}
	}
	sb.WriteString(fmt.Sprintf("%s%s%s", X_bold, report.URL, X_reset))
	renderSection("Query Params", report.QueryParameters)
	renderSection("Headers", report.Headers)
	renderSection("JSON Body", report.DOM)
	renderSection("Open Redirect", report.OpenRedirect)
	renderSection("Location Injection", report.LocationInjection)
	return sb.String()
}

func dedupeConfirmedURLs(urls []string) []string {
	seen := make(map[string]bool)
	var unique []string
	for _, u := range urls {
		normalized := u
		uParsed, err := url.Parse(u)
		if err == nil {
			q := uParsed.Query()
			newQuery := url.Values{}
			for k, v := range q {
				val := v[0]
				val = redactX9(val)
				newQuery.Set(k, val)
			}
			uParsed.RawQuery = newQuery.Encode()
			uParsed.Fragment = redactX9(uParsed.Fragment)
			if uParsed.Path == "/" {
				uParsed.Path = ""
			}
			normalized = uParsed.String()
		} else {
			normalized = redactX9(u)
		}

		if !seen[normalized] {
			seen[normalized] = true
			unique = append(unique, u)
		}
	}
	return unique
}

func (tg *Telegram) sendMessage(text string) {
	if tg == nil {
		return
	}
	payload := map[string]interface{}{
		"chat_id":                  tg.ChatID,
		"text":                     text,
		"parse_mode":               "HTML",
		"disable_web_page_preview": true,
	}
	body, _ := json.Marshal(payload)
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", tg.Token)

	ratelimit.Acquire(apiURL)
	client := ratelimit.GetHTTPClient(apiURL)
	client.Post(apiURL, "application/json", bytes.NewReader(body))
}

func (tg *Telegram) notify(report VulnerabilityReport) {
	if !report.HasVulns() {
		return
	}

	if _, loaded := vulnerableMap.LoadOrStore(report.URL, true); !loaded {
		atomic.AddInt64(&vulnerableTargets, 1)
	}

	reportJSON, _ := json.MarshalIndent(report, "", "  ")
	formatted := dedupeNucleiFindings(report)

	mu.Lock()
	fmt.Printf("\n%s[VULN FOUND]%s\n%s\n", X_red+X_bold, X_reset, formatted)
	mu.Unlock()

	vulnDir := filepath.Join(outputDir, "vulnerabilities")
	os.MkdirAll(vulnDir, 0755)
	safeNameStr := regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(report.URL, "_")
	fileName := filepath.Join(vulnDir, safeNameStr+".json")
	os.WriteFile(fileName, reportJSON, 0644)

	if tg == nil {
		return
	}

	hasConfirmed := false
	hasValidCandidate := false
	totalVulns := 0
	noisyDOMVulns := 0

	checkList := [][]Vulnerability{report.QueryParameters, report.Headers, report.JSONBody, report.DOM, report.OpenRedirect, report.LocationInjection}
	for _, list := range checkList {
		for _, v := range list {
			totalVulns++
			if v.Severity == "confirmed" || v.Confirmed {
				hasConfirmed = true
			} else if v.Severity == "likely" {
				hasValidCandidate = true
			} else if v.Severity == "possible" {
				if strings.Contains(v.Name, "(Note: No HTTP reflection, possible false positive)") {
					noisyDOMVulns++
				} else {
					hasValidCandidate = true
				}
			}
		}
	}

	if totalVulns > 0 && totalVulns == noisyDOMVulns {
		return
	}

	ts := time.Now().Format("2006-01-02 15:04:05")

	if hasConfirmed {
		var sb strings.Builder
		sb.WriteString("🚨 <b>CONFIRMED XSS</b>\n\n")
		sb.WriteString(fmt.Sprintf("🎯 <b>Target:</b> <code>%s</code>\n", escapeHTML(report.URL)))
		sb.WriteString(fmt.Sprintf("📅 <b>Time:</b> %s\n\n", ts))
		sb.WriteString(fmt.Sprintf("<pre>%s</pre>", escapeHTML(string(reportJSON))))
		tg.sendMessage(sb.String())

	} else if hasValidCandidate {
		if _, loaded := candidateNotified.LoadOrStore(report.URL, true); !loaded {
			var sb strings.Builder
			sb.WriteString("🔎 <b>Candidate findings</b>\n\n")
			sb.WriteString(fmt.Sprintf("🎯 <b>Target:</b> <code>%s</code>\n", escapeHTML(report.URL)))
			sb.WriteString(fmt.Sprintf("📅 <b>Time:</b> %s\n\n", ts))

			sb.WriteString("<b>Summary of Findings:</b>\n")
			if len(report.QueryParameters) > 0 {
				sb.WriteString(fmt.Sprintf("- Query Parameters: %d\n", len(report.QueryParameters)))
			}
			if len(report.Headers) > 0 {
				sb.WriteString(fmt.Sprintf("- Headers: %d\n", len(report.Headers)))
			}
			if len(report.JSONBody) > 0 {
				sb.WriteString(fmt.Sprintf("- JSON Body: %d\n", len(report.JSONBody)))
			}
			if len(report.DOM) > 0 {
				sb.WriteString(fmt.Sprintf("- DOM: %d\n", len(report.DOM)))
			}
			if len(report.OpenRedirect) > 0 {
				sb.WriteString(fmt.Sprintf("- Open Redirect: %d\n", len(report.OpenRedirect)))
			}
			if len(report.LocationInjection) > 0 {
				sb.WriteString(fmt.Sprintf("- Location Injection: %d\n", len(report.LocationInjection)))
			}

			tg.sendMessage(sb.String())
		}
	}
}

func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// ── UI and Logging ────────────────────────────────────────────────────────────

const (
	X_reset  = "\033[0m"
	X_bold   = "\033[1m"
	X_red    = "\033[31m"
	X_green  = "\033[32m"
	X_yellow = "\033[33m"
	X_blue   = "\033[34m"
	X_purple = "\033[35m"
	X_cyan   = "\033[36m"
	X_gray   = "\033[90m"
	X_white  = "\033[97m"
)

var (
	outputDir            string
	nucleiTemplate       string
	domTemplate          string
	canaryTemplate       string
	paramFile            string
	techFlag             string
	forceAll             bool
	concurrency          int
	workers              int
	domScanEnabled       bool
	fastWorkers          int
	mu                   sync.Mutex
	tg                   *Telegram
	allCrawledURLs       []string
	maxURLsPerTarget     int
	allowWildcards       bool
	processedTargets     int64
	vulnerableTargets    int64
	vulnerableMap        sync.Map
	workerLock           sync.Map
	candidateNotified    sync.Map
	nucleiExists         bool
	domSinkCheckerExists bool
	curlCheckerExists    bool
	skipSPA              bool

	consecutiveDead int64
	phase           int

	reX9       = regexp.MustCompile(`(?:<b9|['"])?x9(?:canary)?[a-z]*(?:['"\;<{]|\{\{)?`)
	rePayload  = regexp.MustCompile(`\[(?:"([^"]+)"|([^"\]]+))\]$`)
	reANSI     = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	reCleaning = regexp.MustCompile(`\s*\["0m"\]\s*`)

	triageMu      sync.Mutex
	triageEntries []TriageEntry
)

var aliveProbeTimeout = 12

type TriageEntry struct {
	TargetURL    string
	ParamsCount  int
	DomCount     int
	HeadersCount int
}

func logLine(level, color, format string, args ...interface{}) {
	ts := time.Now().Format("15:04:05")
	fmt.Printf("%s[%s]%s %s[%s]%s %s\n", X_gray, ts, X_reset, color, level, X_reset, fmt.Sprintf(format, args...))
}

func stripANSI(str string) string {
	return reANSI.ReplaceAllString(str, "")
}

func extractRootDomain(hostname string) string {
	parts := strings.Split(hostname, ".")
	if len(parts) <= 2 {
		return hostname
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func isInScope(targetURL, rawURL string) bool {
	tParsed, errT := url.Parse(targetURL)
	uParsed, errU := url.Parse(rawURL)
	if errT != nil || errU != nil {
		return false
	}

	rootDomain := extractRootDomain(tParsed.Hostname())
	urlDomain := uParsed.Hostname()

	return urlDomain == rootDomain || strings.HasSuffix(urlDomain, "."+rootDomain)
}

func isConcreteURL(rawURL string) bool {
	if allowWildcards {
		return true
	}
	decoded, _ := url.QueryUnescape(rawURL)
	if strings.Contains(decoded, "*") {
		return false
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	for _, seg := range strings.Split(parsed.Path, "/") {
		decoded, _ := url.QueryUnescape(seg)
		if decoded == "*" {
			return false
		}
	}
	return true
}

func isTargetAlive(targetURL string) (alive bool, wafChallenge bool) {
	ratelimit.Acquire(targetURL)

	u, err := url.Parse(targetURL)
	if err != nil {
		return false, false
	}
	u.Fragment = ""
	checkURL := u.String()

	attempts := []struct {
		method  string
		timeout int
	}{
		{"HEAD", aliveProbeTimeout},
		{"HEAD", aliveProbeTimeout * 2},
		{"GET", aliveProbeTimeout},
		{"GET", aliveProbeTimeout * 2},
	}

	for i, a := range attempts {
		statusCode, _, respBody, _ := curlRequest(checkURL, a.method, nil, "", a.timeout)

		if statusCode == 0 {
			if i == len(attempts)-1 {
				return false, false
			}
			continue
		}

		wafDetected := false
		if detectWAFChallenge(statusCode, respBody) {
			atomic.AddInt64(&wafChallengeDetected, 1)
			logLine("WAF-CHALLENGE", X_yellow, "WAF Challenge page detected on %s", targetURL)
			wafDetected = true
		}

		return true, wafDetected
	}

	return false, false
}

func checkConnectivity() bool {
	conn, err := net.DialTimeout("tcp", "8.8.8.8:53", 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

var runCommandTimeout = 5 * time.Minute

func runCommand(name string, args ...string) (string, error) {
	if name == "nuclei" && !nucleiExists {
		return "", nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), runCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()

	if ctx.Err() == context.DeadlineExceeded {
		if cmd.Process != nil {
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return out.String(), fmt.Errorf("runCommand: %s timed out after %s", name, runCommandTimeout)
	}

	return out.String(), err
}

func extractURLsFromNuclei(nucleiOutput string) []string {
	var urls []string
	scanner := bufio.NewScanner(strings.NewReader(nucleiOutput))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		for _, part := range parts {
			if strings.HasPrefix(part, "http://") || strings.HasPrefix(part, "https://") {
				urlPart := strings.Trim(part, "[]")
				urls = append(urls, urlPart)
				break
			}
		}
	}
	return urls
}

// ── Generic Reflector Detection ─────────────────────────────────────────────

func isGenericReflector(targetURL string) bool {
	u, err := url.Parse(targetURL)
	if err != nil {
		return false
	}
	u.Fragment = ""
	q := u.Query()
	q.Set("xprobe1", "CANARY_A")
	q.Set("xprobe2", "CANARY_B")
	q.Set("xprobe3", "CANARY_C")
	q.Set("xprobe4", "CANARY_D")
	q.Set("xprobe5", "CANARY_E")

	cbName := "_cb"
	_, exists := q[cbName]
	for exists {
		cbName = "_cb" + randomString(3)
		_, exists = q[cbName]
	}
	q.Set(cbName, fmt.Sprintf("%d_%s", time.Now().UnixNano(), randomString(4)))

	u.RawQuery = q.Encode()
	finalURL := u.String()

	ratelimit.Acquire(finalURL)

	statusCode, _, respBody, err := curlRequest(finalURL, "GET", nil, "", 10)
	if err != nil || statusCode == 0 {
		return false
	}

	body := string(respBody)
	canaries := []string{"CANARY_A", "CANARY_B", "CANARY_C", "CANARY_D", "CANARY_E"}
	count := 0
	for _, c := range canaries {
		if strings.Contains(body, c) {
			count++
		}
	}
	return count >= 4
}

// ── Core Logic ────────────────────────────────────────────────────────────────

func randomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyz")
	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}

func reflectionExistsVerified(targetURL, method string, headers map[string]string, reqBody, payload string, markerChar byte) (bool, bool, map[string]string) {
	ratelimit.Acquire(targetURL)

	finalURL := targetURL
	if method == "GET" {
		if u, err := url.Parse(targetURL); err == nil {
			q := u.Query()
			cbName := "_cb"
			_, exists := q[cbName]
			for exists {
				cbName = "_cb" + randomString(3)
				_, exists = q[cbName]
			}
			q.Set(cbName, fmt.Sprintf("%d_%s", time.Now().UnixNano(), randomString(4)))
			u.RawQuery = q.Encode()
			finalURL = u.String()
		}
	}

	statusCode, respHeaders, respBody, err := curlRequest(finalURL, method, headers, reqBody, 15)
	if err != nil || statusCode == 0 {
		return false, true, nil
	}

	bareCanary := reflectctx.ExtractCanary(payload)
	isConfirmed, _ := reflectctx.VerifyBreakout(respBody, bareCanary, markerChar)

	return isConfirmed, false, respHeaders
}

func doubleEncode(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "'", "%2527")
	s = strings.ReplaceAll(s, "\"", "%2522")
	s = strings.ReplaceAll(s, "<", "%253C")
	s = strings.ReplaceAll(s, ">", "%253E")
	return s
}

func reflectionExistsVerifiedPair(targetURL, method string, headers map[string]string, reqBody, payload string, markerChar byte, canary string) (bool, string, bool, map[string]string) {
	ratelimit.Acquire(targetURL)

	finalURL := targetURL
	if method == "GET" {
		if u, err := url.Parse(targetURL); err == nil {
			q := u.Query()
			cbName := "_cb"
			_, exists := q[cbName]
			for exists {
				cbName = "_cb" + randomString(3)
				_, exists = q[cbName]
			}
			q.Set(cbName, fmt.Sprintf("%d_%s", time.Now().UnixNano(), randomString(4)))
			u.RawQuery = q.Encode()
			finalURL = u.String()
		}
	}

	statusCode, respHeaders, respBody, err := curlRequest(finalURL, method, headers, reqBody, 15)
	if err != nil || statusCode == 0 {
		return false, "", true, nil
	}

	isConfirmed, reflType := reflectctx.VerifyBreakoutPair(respBody, canary, markerChar)

	return isConfirmed, reflType, false, respHeaders
}

func confirmParameter(targetURL, phase, name string) (bool, []string, bool, bool, string) {
	prefix := "x9" + randomString(3)

	type pSpec struct {
		payload string
		marker  byte
	}

	specs := []pSpec{
		{prefix + "'" + randomString(6), '\''},
		{prefix + "\"" + randomString(6), '"'},
		{prefix + "</test", '<'},
	}

	var confirmed []string
	var finalHasCSP, finalAllowsInline bool
	consecutiveFails := 0
	bestReflType := ""

	for _, spec := range specs {
		for _, doDoubleEncode := range []bool{false, true} {
			payloadToSend := spec.payload
			if doDoubleEncode {
				payloadToSend = doubleEncode(spec.payload)
			}

			method := "GET"
			headers := make(map[string]string)
			reqBody := ""
			finalURL := targetURL

			u, err := url.Parse(targetURL)
			if err != nil {
				continue
			}

			switch phase {
			case "get":
				q := u.Query()
				q.Set(name, payloadToSend)
				u.RawQuery = q.Encode()
				finalURL = u.String()
			case "header":
				headers[name] = payloadToSend
			case "json":
				method = "POST"
				data := make(map[string]interface{})
				data[name] = payloadToSend
				b, _ := json.Marshal(data)
				reqBody = string(b)
			}

			_, reflType, isHardFail, respHeaders := reflectionExistsVerifiedPair(finalURL, method, headers, reqBody, payloadToSend, spec.marker, prefix)

			if isHardFail {
				consecutiveFails++
				if consecutiveFails >= 3 {
					logLine("DEAD-MIDSCAN", X_yellow, "%s: 3 consecutive connection failures during confirm, aborting remaining payloads for parameter %s", targetURL, name)
					break
				}
			} else {
				consecutiveFails = 0
			}

			if reflType != "" {
				confirmed = append(confirmed, payloadToSend)
				allowsInline, hasCSP := extractCSP(respHeaders)
				finalHasCSP = hasCSP
				finalAllowsInline = allowsInline

				if reflType == "breakout_confirmed_quote" || reflType == "breakout_confirmed_tag" {
					bestReflType = reflType
				} else if bestReflType == "" {
					bestReflType = reflType
				}
			}
		}
		if consecutiveFails >= 3 {
			break
		}
	}
	return len(confirmed) > 0, confirmed, finalHasCSP, finalAllowsInline, bestReflType
}

func reflectionExists(targetURL, method string, headers map[string]string, body, payload string) bool {
	ratelimit.Acquire(targetURL)

	finalURL := targetURL

	if method == "GET" {
		if u, err := url.Parse(targetURL); err == nil {
			q := u.Query()
			cbName := "_cb"
			_, exists := q[cbName]
			for exists {
				cbName = "_cb" + randomString(3)
				_, exists = q[cbName]
			}
			cbValue := fmt.Sprintf("%d_%s", time.Now().UnixNano(), randomString(4))
			q.Set(cbName, cbValue)
			u.RawQuery = q.Encode()
			finalURL = u.String()
		}
	}

	statusCode, _, respBody, err := curlRequest(finalURL, method, headers, body, 15)
	if err != nil || statusCode == 0 {
		return false
	}

	return strings.Contains(string(respBody), payload)
}

func checkHeaderReflection(targetURL, headerName, headerValue string) bool {
	headers := map[string]string{headerName: headerValue}
	return reflectionExists(targetURL, "GET", headers, "", headerValue)
}

func extractBreakChars(val string) []string {
	idx := strings.LastIndex(val, "x9")
	if idx == -1 {
		return nil
	}
	suffix := val[idx:]
	breakChars := []string{"'", `"`, "`", "<", ";", "{{"}
	found := []string{}
	for _, bc := range breakChars {
		if strings.Contains(suffix, bc) {
			already := false
			for _, f := range found {
				if f == bc {
					already = true
					break
				}
			}
			if !already {
				found = append(found, bc)
			}
		}
	}
	return found
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ── New helpers for curl_reflect_checker ──────────────────────────────────

func extractReflectedURLsFromCurl(output string) []string {
	var urls []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var domOut DomSinkOutput
		if err := json.Unmarshal([]byte(line), &domOut); err != nil {
			continue
		}
		found := false
		for _, sink := range domOut.Sinks {
			if sink == "body_reflection" {
				found = true
				break
			}
		}
		if found && domOut.URL != "" {
			urls = append(urls, domOut.URL)
		}
	}
	return urls
}

func aggregateCurlFindings(report *VulnerabilityReport, reflectedURLs []string, phase string, targetBase string) {
	if len(reflectedURLs) == 0 {
		return
	}

	paramMap := make(map[string]*Vulnerability)

	for _, u := range reflectedURLs {
		payload := reX9.FindString(u)
		if payload == "" {
			continue
		}

		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		var paramName string
		for k, v := range parsed.Query() {
			for _, val := range v {
				if strings.Contains(val, payload) {
					paramName = k
					break
				}
			}
			if paramName != "" {
				break
			}
		}
		if paramName == "" {
			continue
		}

		switch phase {
		case "get":
			if existing, ok := paramMap[paramName]; ok {
				exists := false
				for _, p := range existing.Payloads {
					if p == payload {
						exists = true
						break
					}
				}
				if !exists {
					existing.Payloads = append(existing.Payloads, payload)
				}
				if severityWeight("confirmed") > severityWeight(existing.Severity) {
					existing.Severity = "confirmed"
				}
				existing.Confirmed = true
			} else {
				paramMap[paramName] = &Vulnerability{
					Name:      paramName,
					Severity:  "confirmed",
					Payloads:  []string{payload},
					Confirmed: true,
				}
			}
		case "json":
			cleanURL := *parsed
			q := cleanURL.Query()
			q.Del(paramName)
			cleanURL.RawQuery = q.Encode()
			cleanTarget := cleanURL.String()

			jsonBody := fmt.Sprintf(`{"%s":"%s"}`, paramName, payload)

			if !verifyReflection(cleanTarget, "POST", nil, jsonBody, payload) {
				continue
			}

			if existing, ok := paramMap[paramName]; ok {
				exists := false
				for _, p := range existing.Payloads {
					if p == payload {
						exists = true
						break
					}
				}
				if !exists {
					existing.Payloads = append(existing.Payloads, payload)
				}
				if existing.Severity != "likely" {
					existing.Severity = "likely"
				}
			} else {
				paramMap[paramName] = &Vulnerability{
					Name:      paramName,
					Severity:  "likely",
					Payloads:  []string{payload},
					Confirmed: false,
				}
			}
		}
	}

	if len(paramMap) > 0 {
		targetSlice := &report.QueryParameters
		if phase == "json" {
			targetSlice = &report.JSONBody
		}
		for _, vuln := range paramMap {
			found := false
			for i, existing := range *targetSlice {
				if existing.Name == vuln.Name {
					for _, p := range vuln.Payloads {
						exists := false
						for _, ep := range existing.Payloads {
							if ep == p {
								exists = true
								break
							}
						}
						if !exists {
							(*targetSlice)[i].Payloads = append((*targetSlice)[i].Payloads, p)
						}
					}
					if severityWeight(vuln.Severity) > severityWeight(existing.Severity) {
						(*targetSlice)[i].Severity = vuln.Severity
					}
					if vuln.Confirmed {
						(*targetSlice)[i].Confirmed = true
					}
					found = true
					break
				}
			}
			if !found {
				*targetSlice = append(*targetSlice, *vuln)
			}
		}
	}
}

func extractLocationURLsFromCurl(output string) (openRedirects []string, headerInjections []string) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var domOut DomSinkOutput
		if err := json.Unmarshal([]byte(line), &domOut); err != nil {
			continue
		}
		for _, sink := range domOut.Sinks {
			if sink == "location_open_redirect" && domOut.URL != "" {
				openRedirects = append(openRedirects, domOut.URL)
			} else if sink == "location_header_injection" && domOut.URL != "" {
				headerInjections = append(headerInjections, domOut.URL)
			}
		}
	}
	return
}

func aggregateLocationFindings(report *VulnerabilityReport, openRedirects []string, headerInjections []string) {
	processList := func(urls []string, targetSlice *[]Vulnerability, isRedirect bool) {
		paramMap := make(map[string]*Vulnerability)
		for _, u := range urls {
			payload := reX9.FindString(u)
			if payload == "" {
				continue
			}
			parsed, err := url.Parse(u)
			if err != nil {
				continue
			}
			var paramName string
			for k, v := range parsed.Query() {
				for _, val := range v {
					if strings.Contains(val, payload) {
						paramName = k
						break
					}
				}
				if paramName != "" {
					break
				}
			}
			if paramName == "" {
				continue
			}

			severity := "likely"
			confirmed := false

			if isRedirect {
				randDomain := fmt.Sprintf("https://x9attacker-%s.test", randomString(6))
				cleanURL := *parsed
				q := cleanURL.Query()
				q.Set(paramName, randDomain)
				cleanURL.RawQuery = q.Encode()
				verifyURL := cleanURL.String()

				ratelimit.Acquire(verifyURL)
				status, respHeaders, _, err := curlRequest(verifyURL, "GET", nil, "", 15)
				if err == nil && status >= 300 && status < 400 {
					if loc, ok := respHeaders["location"]; ok {
						if strings.Contains(loc, randDomain) {
							severity = "confirmed"
							confirmed = true
						}
					}
				}
			}

			if existing, ok := paramMap[paramName]; ok {
				exists := false
				for _, p := range existing.Payloads {
					if p == payload {
						exists = true
						break
					}
				}
				if !exists {
					existing.Payloads = append(existing.Payloads, payload)
				}
				if severityWeight(severity) > severityWeight(existing.Severity) {
					existing.Severity = severity
					existing.Confirmed = confirmed
				}
			} else {
				paramMap[paramName] = &Vulnerability{
					Name:      paramName,
					Severity:  severity,
					Payloads:  []string{payload},
					Confirmed: confirmed,
				}
			}
		}

		if len(paramMap) > 0 {
			for _, vuln := range paramMap {
				found := false
				for i, existing := range *targetSlice {
					if existing.Name == vuln.Name {
						for _, p := range vuln.Payloads {
							exists := false
							for _, ep := range existing.Payloads {
								if ep == p {
									exists = true
									break
								}
							}
							if !exists {
								(*targetSlice)[i].Payloads = append((*targetSlice)[i].Payloads, p)
							}
						}
						if severityWeight(vuln.Severity) > severityWeight(existing.Severity) {
							(*targetSlice)[i].Severity = vuln.Severity
						}
						if vuln.Confirmed {
							(*targetSlice)[i].Confirmed = true
						}
						found = true
						break
					}
				}
				if !found {
					*targetSlice = append(*targetSlice, *vuln)
				}
			}
		}
	}

	processList(openRedirects, &report.OpenRedirect, true)
	processList(headerInjections, &report.LocationInjection, false)
}

type ProbeArtifacts struct {
	TargetURL         string
	Index             int
	Total             int
	Profile           TechProfile
	HasJS             bool
	TargetAlive       bool
	ProbeOutputBase   string
	DomQueryProbeFile string
	TriageOnly        bool
	GetParamSet       map[string]bool
	GetReflectedRaw   []string
	CandidateHeaders  []string
	Skip              bool
	WAFBlocked        bool // NEW FIELD
}

func processURLFast(targetURL string, index, total int) ProbeArtifacts {
	art := ProbeArtifacts{TargetURL: targetURL, Index: index, Total: total}

	uParsed, err := url.Parse(targetURL)
	if err != nil || uParsed == nil {
		logLine("SKIP", X_yellow, "unparseable URL, skipping: %s", targetURL)
		art.Skip = true
		return art
	}
	normalizedLockURL := targetURL
	uParsed.Path = strings.TrimSuffix(uParsed.Path, "/")
	if strings.HasSuffix(uParsed.Path, "/index.php") {
		uParsed.Path = strings.TrimSuffix(uParsed.Path, "/index.php")
	}
	if strings.HasSuffix(uParsed.Path, "/index.html") {
		uParsed.Path = strings.TrimSuffix(uParsed.Path, "/index.html")
	}
	normalizedLockURL = uParsed.String()

	if _, loaded := workerLock.LoadOrStore(normalizedLockURL, true); loaded {
		art.Skip = true
		return art
	}

	atomic.AddInt64(&processedTargets, 1)
	currProcessed := atomic.LoadInt64(&processedTargets)
	currVulns := atomic.LoadInt64(&vulnerableTargets)

	logLine("TARGET", X_white, "[%d/%d | Vulns: %d] %s", currProcessed, total, currVulns, targetURL)

	if !skipSPA && spadetect.IsSPA(targetURL) {
		logLine("SKIP", X_yellow, "SPA/React detected, skipping heavy scan for %s", targetURL)
		art.Skip = true
		return art
	}

	if isGenericReflector(targetURL) {
		logLine("SKIP", X_yellow, "Generic reflector detected, skipping %s", targetURL)
		art.Skip = true
		return art
	}

	techListStr := strings.Split(techFlag, ",")
	profile := classifyTechProfile(techListStr)
	art.Profile = profile

	report := VulnerabilityReport{URL: targetURL}

	probeInput := filepath.Join(outputDir, safeName(targetURL)+"-probe-in.txt")
	os.WriteFile(probeInput, []byte(targetURL), 0644)

	probeOutputBase := filepath.Join(outputDir, safeName(targetURL)+"-probe-out")
	art.ProbeOutputBase = probeOutputBase

	// 1. Initial Probe Invocation
	xArgs := []string{"-probe", "-json", "-headers", "-dom"}
	if paramFile != "" {
		xArgs = append(xArgs, "-p", paramFile)
	}
	// Execute probe with expanded args
	runCommand("./x9", xArgs...)

	// ... [intermediate code] ...

	// 2. Attack-Stage Invocation
	atkArgs := []string{"-i", atkIn, "-json", "-headers", "-o", finalX9Base}
	if paramFile != "" {
		atkArgs = append(atkArgs, "-p", paramFile)
	}
	runCommand("./x9", atkArgs...)

	domQueryProbeFile := filepath.Join(outputDir, safeName(targetURL)+"-dom-query-probe.txt")
	art.DomQueryProbeFile = domQueryProbeFile
	paramsToProbe := []string{}
	if paramFile != "" {
		if pf, err := os.Open(paramFile); err == nil {
			scanner := bufio.NewScanner(pf)
			for scanner.Scan() {
				if p := strings.TrimSpace(scanner.Text()); p != "" {
					paramsToProbe = append(paramsToProbe, p)
				}
			}
			pf.Close()
		}
	}
	if len(paramsToProbe) == 0 {
		paramsToProbe = []string{
			"q", "s", "search", "id", "url", "redirect", "next", "return",
			"callback", "code", "token", "data", "input", "value", "text",
			"name", "message", "template", "write", "timeout", "src", "frame",
			"href", "goto", "dest", "destination", "target",
		}
	}

	if len(paramsToProbe) > 0 {
		var domProbeURLs []string
		for _, param := range paramsToProbe {
			canary := "x9canary" + randomString(3)
			u, err := url.Parse(targetURL)
			if err != nil {
				continue
			}
			q := u.Query()
			q.Set(param, canary)
			u.RawQuery = q.Encode()
			domProbeURLs = append(domProbeURLs, u.String())
		}
		if len(domProbeURLs) > 0 {
			os.WriteFile(domQueryProbeFile, []byte(strings.Join(domProbeURLs, "\n")), 0644)
		}
	}

	logLine("PHASE2", X_gray, "probe files generated for %s", targetURL)

	if phase < 3 {
		art.Skip = true
		return art
	}

	targetAlive, wafDetected := isTargetAlive(targetURL)
	var hasJS bool
	if targetAlive {
		hasJS = hasClientSideJSRisk(targetURL)
		atomic.StoreInt64(&consecutiveDead, 0)

		// --- BEGIN CORS INTEGRATION ---
		corsFindings := corscheck.CheckCORS(targetURL)
		for _, finding := range corsFindings {
			if repLogger != nil {
				repLogger.Log(reporter.NewFinding(
					extractRootDomain(uParsed.Hostname()),
					targetURL,
					finding.Origin,
					"corscheck",
					finding.Confidence,
					"cors_misconfig",
					reporter.Context{
						Location:     finding.Variant,
						AllowedChars: []string{finding.ReflectedACAO},
					},
				))
			}

			// Only output HIGH confidence findings to stdout to avoid terminal noise
			if finding.Confidence == "HIGH" {
				logLine("CORS", X_yellow, "%s: CORS misconfig (%s, origin=%s, creds=%v)",
					targetURL, finding.Confidence, finding.Origin, finding.AllowCredentials)
			}
		}
		// --- END CORS INTEGRATION ---

	} else {
		newCount := atomic.AddInt64(&consecutiveDead, 1)
		if newCount%5 == 0 {
			for !checkConnectivity() {
				logLine("WARN", X_yellow, "Network connectivity lost — pausing scan for 30 seconds")
				time.Sleep(30 * time.Second)
			}
		}
	}
	art.TargetAlive = targetAlive
	art.HasJS = hasJS
	art.WAFBlocked = wafDetected // Capture WAF state immediately

	probeFiles := map[string]string{
		probeOutputBase + ".get":    "get",
		probeOutputBase + ".json":   "json",
		probeOutputBase + ".header": "header",
	}

	p3Findings := make(map[string][]string)
	candidateHeaders := []string{}

	for pf, probePhase := range probeFiles {
		if _, err := os.Stat(pf); err == nil {

			if probePhase == "header" {
				if profile.IsSPA && !forceAll {
					logLine("SKIP-TECH", X_cyan, "Skipping header injection for %s due to detected SPA tech: %s", targetURL, techFlag)
					continue
				}

				file, err := os.Open(pf)
				if err != nil {
					continue
				}
				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if line == "" {
						continue
					}
					parts := strings.SplitN(line, "|", 2)
					if len(parts) != 2 {
						continue
					}
					urlPart := parts[0]
					headerPart := parts[1]
					headerParts := strings.SplitN(headerPart, ":", 2)
					if len(headerParts) != 2 {
						continue
					}
					headerName := strings.TrimSpace(headerParts[0])
					headerValue := strings.TrimSpace(headerParts[1])

					if checkHeaderReflection(urlPart, headerName, headerValue) {
						found := false
						for _, h := range candidateHeaders {
							if h == headerName {
								found = true
								break
							}
						}
						if !found {
							candidateHeaders = append(candidateHeaders, headerName)
						}
					}
				}
				file.Close()

			} else {
				if curlCheckerExists {
					res, err := runCommand("./curl_reflect_checker", "-l", pf)
					if err != nil {
						logLine("CURLCHECK-ERR", X_red, "%s (%s): curl_reflect_checker exited with error: %v", targetURL, pf, err)
					} else if res == "" {
						logLine("CURLCHECK-EMPTY", X_yellow, "%s (%s): curl_reflect_checker ran but returned no output", targetURL, pf)
					}
					if res != "" {
						reflectedURLs := extractReflectedURLsFromCurl(res)
						probedCount := countLines(pf)
						logLine("CURLCHECK-RESULT", X_cyan, "%s: %d URLs probed -> %d reflections found", pf, probedCount, len(reflectedURLs))
						p3Findings[probePhase] = append(p3Findings[probePhase], reflectedURLs...)
					}

					if probePhase == "get" {
						resLoc, errLoc := runCommand("./curl_reflect_checker", "-l", pf, "-check-location", "-xss")
						if errLoc != nil {
							logLine("CURLCHECK-ERR", X_red, "%s (%s): curl_reflect_checker (location) exited with error: %v", targetURL, pf, errLoc)
						} else if resLoc == "" {
							logLine("CURLCHECK-EMPTY", X_yellow, "%s (%s): curl_reflect_checker (location) ran but returned no output", targetURL, pf)
						}

						if resLoc != "" {
							openRedirects, headerInjections := extractLocationURLsFromCurl(resLoc)
							logLine("CURLCHECK-RESULT", X_cyan, "%s: %d URLs location probed -> %d open-redirects, %d header-injections", pf, countLines(pf), len(openRedirects), len(headerInjections))
							aggregateLocationFindings(&report, openRedirects, headerInjections)
						}
					}
				} else {
					logLine("WARN", X_yellow, "curl_reflect_checker not available, skipping reflection check for %s", pf)
				}
			}
		}
	}

	getParamSet := make(map[string]bool)
	for _, u := range p3Findings["get"] {
		parsed, err := url.Parse(u)
		if err == nil {
			for k := range parsed.Query() {
				getParamSet[k] = true
			}
		}
	}
	var getParams []string
	for k := range getParamSet {
		getParams = append(getParams, k)
	}
	sort.Strings(getParams)

	headers := candidateHeaders
	sort.Strings(headers)

	art.GetParamSet = getParamSet
	art.GetReflectedRaw = append([]string(nil), p3Findings["get"]...)
	art.CandidateHeaders = append([]string(nil), headers...)

	if len(getParamSet) > 0 || len(headers) > 0 {
		paramsStr := strings.Join(getParams, ", ")
		if paramsStr == "" {
			paramsStr = "none"
		}
		headersStr := strings.Join(headers, ", ")
		if headersStr == "" {
			headersStr = "none"
		}
		logLine("HIT-HTTP", X_green, "%s → params: %s | headers: %s", targetURL, paramsStr, headersStr)
	} else {
		logLine("CLEAN-HTTP", X_gray, "%s", targetURL)
	}

	if phase == 3 {
		art.TriageOnly = true
		return art
	}

	if len(p3Findings) == 0 && len(candidateHeaders) == 0 {
		return art
	}

	// If WAF was detected at the start, log it and gate the heavy phases.
	if art.WAFBlocked {
		logLine("WAF-BLOCKED", X_yellow, "%s: WAF challenge detected — recording %d candidate params/headers but skipping confirm+attack (manual review recommended)", targetURL, len(getParamSet)+len(candidateHeaders))
	} else {
		// Mid-scan re-check #1 (Before Phase 4b)
		targetAlive, wafDetected = isTargetAlive(targetURL)
		if !targetAlive || wafDetected {
			if !targetAlive {
				logLine("DEAD-MIDSCAN", X_yellow, "%s went dead before Phase 4b, skipping confirm+attack", targetURL)
			} else {
				logLine("WAF-CHALLENGE-MIDSCAN", X_yellow, "%s: WAF challenge re-confirmed before heavy phase, skipping remaining attack steps", targetURL)
			}
			art.TargetAlive = targetAlive
			if report.HasVulns() {
				tg.notify(report)
			}
			logReportFindings(&report)
			return art
		}
	}

	confirmedParams := make(map[string]map[string]bool)
	for p := range p3Findings {
		confirmedParams[p] = make(map[string]bool)
	}

	// ALWAYS aggregate findings first (so they are reported as candidates if WAF skips confirm/attack)
	for probePhase, urls := range p3Findings {
		dummy := ""
		for _, u := range urls {
			dummy += "[canary] [info] " + u + " [x9canary]\n"
		}
		report.aggregateFindings(dummy, probePhase)

		// Only run confirmParameter heavy-requests if NOT WAF blocked
		if !art.WAFBlocked {
			var vList *[]Vulnerability
			switch probePhase {
			case "get":
				vList = &report.QueryParameters
			case "json":
				vList = &report.JSONBody
			}

			if vList != nil {
				for i := range *vList {
					name := (*vList)[i].Name
					if ok, p, hasCSP, allowsInline, reflType := confirmParameter(targetURL, probePhase, name); ok {
						if reflType == "breakout_confirmed_quote" || reflType == "breakout_confirmed_tag" {
							(*vList)[i].Confirmed = true
							if hasCSP && !allowsInline {
								(*vList)[i].Severity = "likely"
								note := " (Note: Reflected but page has strict CSP; inline execution likely blocked)"
								if !strings.Contains((*vList)[i].Name, note) {
									(*vList)[i].Name += note
								}
							} else {
								(*vList)[i].Severity = "confirmed"
							}
						} else if reflType == "simple_reflection" {
							(*vList)[i].Confirmed = false
							(*vList)[i].Severity = "likely"
						}

						(*vList)[i].Payloads = p
						confirmedParams[probePhase][name] = true
					}
				}
			}
		}
	}

	// For candidate headers, ensure they are still recorded even if we skip confirmation
	for _, headerName := range candidateHeaders {
		if art.WAFBlocked {
			report.Headers = append(report.Headers, Vulnerability{
				Name:      headerName,
				Severity:  "possible", // Base candidate confidence
				Confirmed: false,
			})
			continue
		}

		if ok, payloads, hasCSP, allowsInline, reflType := confirmParameter(targetURL, "header", headerName); ok {
			severity := "likely"
			confirmedField := false
			name := headerName

			if reflType == "breakout_confirmed_quote" || reflType == "breakout_confirmed_tag" {
				confirmedField = true
				if hasCSP && !allowsInline {
					severity = "likely"
					name += " (Note: Reflected but page has strict CSP; inline execution likely blocked)"
				} else {
					severity = "confirmed"
				}
			}

			v := Vulnerability{
				Name:      name,
				Severity:  severity,
				Confirmed: confirmedField,
				Payloads:  payloads,
			}
			report.Headers = append(report.Headers, v)
			if confirmedParams["header"] == nil {
				confirmedParams["header"] = make(map[string]bool)
			}
			confirmedParams["header"][headerName] = true
			logLine("CONFIRM", X_green, "Confirmed XSS (header): %s (header: %s)", targetURL, headerName)
		}
	}

	// If WAF was detected, skip Phase 4 completely and return early
	if art.WAFBlocked {
		if report.HasVulns() {
			tg.notify(report)
		}
		logReportFindings(&report)
		return art
	}

	// Mid-scan re-check #2 (Before Phase 4 Attack)
	targetAlive, wafDetected = isTargetAlive(targetURL)
	if !targetAlive || wafDetected {
		if !targetAlive {
			logLine("DEAD-MIDSCAN", X_yellow, "%s went dead before Phase 4, skipping attack", targetURL)
		} else {
			logLine("WAF-CHALLENGE-MIDSCAN", X_yellow, "%s: WAF challenge re-confirmed before heavy phase, skipping remaining attack steps", targetURL)
		}
		art.TargetAlive = targetAlive
		if report.HasVulns() {
			tg.notify(report)
		}
		logReportFindings(&report)
		return art
	}

	httpAtkUrls := []string{}
	for probePhase, urls := range p3Findings {
		for _, u := range urls {
			uParsedAtk, _ := url.Parse(u)
			if uParsedAtk == nil {
				continue
			}
			isConfirmed := false

			query := uParsedAtk.Query()
			for name := range confirmedParams[probePhase] {
				switch probePhase {
				case "get":
					if _, exists := query[name]; exists {
						isConfirmed = true
					}
				case "json":
					if strings.Contains(u, "\""+name+"\"") {
						isConfirmed = true
					}
				}
				if isConfirmed {
					break
				}
			}
			if !isConfirmed && isInScope(targetURL, u) && isConcreteURL(u) {
				httpAtkUrls = append(httpAtkUrls, u)
			}
		}
	}

	if len(httpAtkUrls) > 0 {
		atkIn := filepath.Join(outputDir, safeName(targetURL)+"-http-atk-in.txt")
		os.WriteFile(atkIn, []byte(strings.Join(dedupeConfirmedURLs(httpAtkUrls), "\n")), 0644)
		finalX9Base := filepath.Join(outputDir, safeName(targetURL)+"-final-http")
		runCommand("./x9", "-i", atkIn, "-json", "-headers", "-o", finalX9Base)

		exts := map[string]string{".get": "get", ".json": "json"}
		for ext, ph := range exts {
			atkFile := finalX9Base + ext
			if _, statErr := os.Stat(atkFile); statErr == nil {
				if curlCheckerExists {
					res, err := runCommand("./curl_reflect_checker", "-l", atkFile, "-xss")
					if err != nil {
						logLine("CURLCHECK-ERR", X_red, "%s (%s): curl_reflect_checker exited with error: %v", targetURL, atkFile, err)
					} else if res == "" {
						logLine("CURLCHECK-EMPTY", X_yellow, "%s (%s): curl_reflect_checker ran but returned no output", targetURL, atkFile)
					}
					if res != "" {
						reflectedURLs := extractReflectedURLsFromCurl(res)
						probedCount := countLines(atkFile)
						logLine("CURLCHECK-RESULT", X_cyan, "%s: %d URLs probed -> %d reflections found", atkFile, probedCount, len(reflectedURLs))
						aggregateCurlFindings(&report, reflectedURLs, ph, targetURL)
					}

					if ph == "get" {
						resLoc, errLoc := runCommand("./curl_reflect_checker", "-l", atkFile, "-check-location", "-xss")
						if errLoc != nil {
							logLine("CURLCHECK-ERR", X_red, "%s (%s): curl_reflect_checker (location) exited with error: %v", targetURL, atkFile, errLoc)
						}
						if resLoc != "" {
							openRedirects, headerInjections := extractLocationURLsFromCurl(resLoc)
							aggregateLocationFindings(&report, openRedirects, headerInjections)
						}
					}
				} else {
					logLine("WARN", X_yellow, "curl_reflect_checker not available, skipping Phase 4 reflection check for %s", atkFile)
				}
			}
		}

		if profile.IsSPA && !forceAll {
			logLine("SKIP-TECH", X_cyan, "Skipping Phase 4 header injection for %s due to detected SPA tech: %s", targetURL, techFlag)
		} else {
			headerAtkFile := finalX9Base + ".header"
			if _, err := os.Stat(headerAtkFile); err == nil {
				file, err := os.Open(headerAtkFile)
				if err == nil {
					scanner := bufio.NewScanner(file)
					for scanner.Scan() {
						line := strings.TrimSpace(scanner.Text())
						if line == "" {
							continue
						}
						parts := strings.SplitN(line, "|", 2)
						if len(parts) != 2 {
							continue
						}
						urlPart := parts[0]
						headerPart := parts[1]
						headerParts := strings.SplitN(headerPart, ":", 2)
						if len(headerParts) != 2 {
							continue
						}
						headerName := strings.TrimSpace(headerParts[0])
						headerValue := strings.TrimSpace(headerParts[1])

						if confirmedParams["header"] != nil && confirmedParams["header"][headerName] {
							continue
						}

						if checkHeaderReflection(urlPart, headerName, headerValue) {
							found := false
							for i, v := range report.Headers {
								if v.Name == headerName {
									exists := false
									for _, p := range v.Payloads {
										if p == headerValue {
											exists = true
											break
										}
									}
									if !exists {
										report.Headers[i].Payloads = append(report.Headers[i].Payloads, headerValue)
									}
									found = true
									break
								}
							}
							if !found {
								report.Headers = append(report.Headers, Vulnerability{
									Name:     headerName,
									Severity: "likely",
									Payloads: []string{headerValue},
								})
							}
							logLine("FIND", X_green, "Found header reflection: %s = %s", headerName, headerValue)
						}
					}
					file.Close()
				}
			}
		}
	}

	if report.HasVulns() {
		tg.notify(report)
	}
	logReportFindings(&report)

	return art
}

func processURLDom(art ProbeArtifacts) VulnerabilityReport {
	report := VulnerabilityReport{URL: art.TargetURL}

	if art.Skip {
		return report
	}

	targetURL := art.TargetURL
	hasJS := art.HasJS
	targetAlive := art.TargetAlive

	p3Findings := make(map[string][]string)
	domProbeSkippedAll := false

	domCanaryFile := art.ProbeOutputBase + ".dom.canary"
	if !domScanEnabled {
		logLine("SKIP-DOM-DISABLED", X_gray, "DOM/headless checks disabled (pass -dom-scan to enable) for %s", targetURL)
	} else {
		if _, err := os.Stat(domCanaryFile); err == nil {
			if !hasJS && !forceAll {
				logLine("SKIP-NOJS", X_cyan, "Skipping DOM checks for %s: no <script> tags detected in page", targetURL)
				domProbeSkippedAll = true
			} else if !targetAlive {
				domProbeSkippedAll = true
			} else if domSinkCheckerExists {
				res, err := runCommand("./dom_sink_checker", "-l", domCanaryFile)
				if err != nil {
					logLine("DOMCHECK-ERR", X_red, "%s (%s): dom_sink_checker exited with error: %v", targetURL, domCanaryFile, err)
				} else if res == "" {
					logLine("DOMCHECK-EMPTY", X_yellow, "%s (%s): dom_sink_checker ran but returned no output", targetURL, domCanaryFile)
				}

				if res != "" {
					lines := strings.Split(strings.TrimSpace(res), "\n")
					for _, l := range lines {
						l = strings.TrimSpace(l)
						var probe DomSinkOutput
						if err := json.Unmarshal([]byte(l), &probe); err == nil && probe.URL != "" {
							p3Findings["dom"] = append(p3Findings["dom"], l)
						}
					}
				}
			}
		}
	}

	if !domScanEnabled {
	} else {
		if _, err := os.Stat(art.DomQueryProbeFile); err == nil {
			if !hasJS && !forceAll {
				logLine("SKIP-NOJS", X_cyan, "Skipping DOM query sink checker for %s: no <script> tags detected in page", targetURL)
				if !targetAlive {
					domProbeSkippedAll = true
				}
			} else if !targetAlive {
				domProbeSkippedAll = true
			} else if domSinkCheckerExists {
				res, err := runCommand("./dom_sink_checker", "-l", art.DomQueryProbeFile)
				if err != nil {
					logLine("DOMCHECK-ERR", X_red, "%s (%s): dom_sink_checker exited with error: %v", targetURL, art.DomQueryProbeFile, err)
				} else if res == "" {
					logLine("DOMCHECK-EMPTY", X_yellow, "%s (%s): dom_sink_checker ran but returned no output", targetURL, art.DomQueryProbeFile)
				}

				if res != "" {
					lines := strings.Split(strings.TrimSpace(res), "\n")
					for _, l := range lines {
						l = strings.TrimSpace(l)
						var probe DomSinkOutput
						if err := json.Unmarshal([]byte(l), &probe); err == nil && probe.URL != "" {
							p3Findings["dom"] = append(p3Findings["dom"], l)
						}
					}
				}
			}
		}
	}

	if domProbeSkippedAll && domScanEnabled && (fileExists(domCanaryFile) || fileExists(art.DomQueryProbeFile)) {
		logLine("DEAD", X_yellow, "%s", targetURL)
	}

	domCount := len(p3Findings["dom"])
	if domCount > 0 {
		logLine("HIT-DOM", X_green, "%s → dom: %d", targetURL, domCount)
	} else if domScanEnabled {
		logLine("CLEAN-DOM", X_gray, "%s", targetURL)
	}

	if art.TriageOnly {
		writeTriageFile(art, p3Findings, domCount)
		return report
	}

	if domCount == 0 {
		return report
	}

	if !domScanEnabled {
	} else {
		var fragmentURLs []string
		for _, line := range p3Findings["dom"] {
			var domOut DomSinkOutput
			if err := json.Unmarshal([]byte(line), &domOut); err != nil {
				continue
			}
			parsed, err := url.Parse(domOut.URL)
			if err == nil && parsed.Fragment != "" && isInScope(targetURL, domOut.URL) && isConcreteURL(domOut.URL) {
				fragmentURLs = append(fragmentURLs, domOut.URL)
			}
		}
		if len(fragmentURLs) > 0 {
			if !hasJS && !forceAll {
				logLine("SKIP-NOJS", X_cyan, "Skipping Phase 4 DOM fragment attack for %s: no <script> tags detected in page", targetURL)
			} else {
				atkIn := filepath.Join(outputDir, safeName(targetURL)+"-dom-atk-in.txt")
				os.WriteFile(atkIn, []byte(strings.Join(dedupeConfirmedURLs(fragmentURLs), "\n")), 0644)
				finalX9Base := filepath.Join(outputDir, safeName(targetURL)+"-final-dom")
				runCommand("./x9", "-i", atkIn, "-dom", "-o", finalX9Base)

				if domSinkCheckerExists {
					atkFile := finalX9Base + ".dom.attack"
					dom, err := runCommand("./dom_sink_checker", "-xss", "-l", atkFile, "-timeout", "300")
					if err != nil {
						logLine("DOMCHECK-ERR", X_red, "%s (%s): dom_sink_checker exited with error: %v", targetURL, atkFile, err)
					} else if dom == "" {
						logLine("DOMCHECK-EMPTY", X_yellow, "%s (%s): dom_sink_checker ran but returned no output", targetURL, atkFile)
					}

					if dom != "" {
						report.aggregateFindings(dom, "dom_confirmed")
					}
				}
			}
		}
	}

	if domScanEnabled {
		for _, line := range p3Findings["dom"] {
			var domOut DomSinkOutput
			if err := json.Unmarshal([]byte(line), &domOut); err != nil {
				continue
			}
			report.processDomJson(domOut, "dom")
		}
	}

	if !domScanEnabled {
	} else {
		var domQueryURLs []string
		for _, line := range p3Findings["dom"] {
			var domOut DomSinkOutput
			if err := json.Unmarshal([]byte(line), &domOut); err != nil {
				continue
			}
			parsed, err := url.Parse(domOut.URL)
			if err == nil && parsed.Fragment == "" && isInScope(targetURL, domOut.URL) && isConcreteURL(domOut.URL) {
				domQueryURLs = append(domQueryURLs, domOut.URL)
			}
		}
		if len(domQueryURLs) > 0 {
			if !hasJS && !forceAll {
				logLine("SKIP-NOJS", X_cyan, "Skipping Phase 4 DOM query attack for %s: no <script> tags detected in page", targetURL)
			} else {
				atkIn := filepath.Join(outputDir, safeName(targetURL)+"-dom-query-atk-in.txt")
				os.WriteFile(atkIn, []byte(strings.Join(dedupeConfirmedURLs(domQueryURLs), "\n")), 0644)
				finalX9Base := filepath.Join(outputDir, safeName(targetURL)+"-final-dom-query")
				runCommand("./x9", "-i", atkIn, "-o", finalX9Base)

				if domSinkCheckerExists {
					atkFile := finalX9Base + ".get"
					dom, err := runCommand("./dom_sink_checker", "-xss", "-l", atkFile, "-timeout", "300")
					if err != nil {
						logLine("DOMCHECK-ERR", X_red, "%s (%s): dom_sink_checker exited with error: %v", targetURL, atkFile, err)
					} else if dom == "" {
						logLine("DOMCHECK-EMPTY", X_yellow, "%s (%s): dom_sink_checker ran but returned no output", targetURL, atkFile)
					}

					if dom != "" {
						report.aggregateFindings(dom, "dom_confirmed")
					}
				}
			}
		}
	}

	if report.HasVulns() {
		tg.notify(report)
	}
	logReportFindings(&report)

	return report
}

func writeTriageFile(art ProbeArtifacts, p3FindingsDom map[string][]string, domCount int) {
	targetURL := art.TargetURL
	getParamSet := art.GetParamSet

	getParams := make([]string, 0, len(getParamSet))
	for k := range getParamSet {
		getParams = append(getParams, k)
	}
	sort.Strings(getParams)

	headers := art.CandidateHeaders

	var triageContent strings.Builder
	triageContent.WriteString(fmt.Sprintf("TARGET: %s\n", targetURL))
	triageContent.WriteString(fmt.Sprintf("SCANNED: %s\n\n", time.Now().Format(time.RFC3339)))

	triageContent.WriteString("[GET PARAMS]\n")
	if len(getParamSet) == 0 {
		triageContent.WriteString("none\n\n")
	} else {
		paramBreaks := make(map[string]map[string]bool)
		for p := range getParamSet {
			paramBreaks[p] = make(map[string]bool)
		}
		for _, u := range art.GetReflectedRaw {
			parsed, err := url.Parse(u)
			if err != nil {
				continue
			}
			for param, values := range parsed.Query() {
				if _, ok := getParamSet[param]; ok {
					for _, val := range values {
						breaks := extractBreakChars(val)
						for _, b := range breaks {
							paramBreaks[param][b] = true
						}
					}
				}
			}
		}
		for _, param := range getParams {
			breaks := []string{}
			for b := range paramBreaks[param] {
				breaks = append(breaks, b)
			}
			sort.Strings(breaks)
			if len(breaks) == 0 {
				triageContent.WriteString(fmt.Sprintf("%s | break_chars: \n", param))
			} else {
				triageContent.WriteString(fmt.Sprintf("%s | break_chars: %s\n", param, strings.Join(breaks, ", ")))
			}
		}
		triageContent.WriteString("\n")
	}

	triageContent.WriteString("[DOM CANARY]\n")
	if !domScanEnabled {
		triageContent.WriteString("skipped (DOM scanning disabled, pass -dom-scan to enable)\n\n")
	} else if domCount == 0 {
		triageContent.WriteString("none\n\n")
	} else {
		for _, line := range p3FindingsDom["dom"] {
			var domOut DomSinkOutput
			if err := json.Unmarshal([]byte(line), &domOut); err == nil {
				sinksStr := strings.Join(domOut.Sinks, ", ")
				triageContent.WriteString(fmt.Sprintf("%s | sinks: %s\n", domOut.URL, sinksStr))
			} else {
				triageContent.WriteString(line + "\n")
			}
		}
		triageContent.WriteString("\n")
	}

	triageContent.WriteString("[HEADERS]\n")
	if len(headers) == 0 {
		triageContent.WriteString("none\n\n")
	} else {
		for _, h := range headers {
			triageContent.WriteString(h + "\n")
		}
		triageContent.WriteString("\n")
	}

	triageFileName := filepath.Join(outputDir, "triage_"+safeName(targetURL)+".txt")
	if err := os.WriteFile(triageFileName, []byte(triageContent.String()), 0644); err != nil {
		logLine("ERROR", X_red, "Failed to write triage file: %v", err)
	}

	triageMu.Lock()
	triageEntries = append(triageEntries, TriageEntry{
		TargetURL:    targetURL,
		ParamsCount:  len(getParamSet),
		DomCount:     domCount,
		HeadersCount: len(headers),
	})
	triageMu.Unlock()
}

var safeNameRe = regexp.MustCompile(`[^a-zA-Z0-9]`)

func safeName(s string) string {
	return safeNameRe.ReplaceAllString(s, "_")
}

func uniqueStrings(slice []string) []string {
	keys := make(map[string]bool)
	var list []string
	for _, entry := range slice {
		u, err := url.Parse(entry)
		if err != nil {
			if !keys[entry] {
				keys[entry] = true
				list = append(list, entry)
			}
			continue
		}
		u.Path = strings.TrimSuffix(u.Path, "/")
		if strings.HasSuffix(u.Path, "/index.php") {
			u.Path = strings.TrimSuffix(u.Path, "/index.php")
		}
		if strings.HasSuffix(u.Path, "/index.html") {
			u.Path = strings.TrimSuffix(u.Path, "/index.html")
		}

		normalized := u.String()
		if !keys[normalized] {
			keys[normalized] = true
			list = append(list, entry)
		}
	}
	return list
}

func countLines(filename string) int {
	file, err := os.Open(filename)
	if err != nil {
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}
	return count
}

func urlSignature(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	path := strings.TrimSuffix(u.Path, "/")
	var paramNames []string
	for k := range u.Query() {
		paramNames = append(paramNames, k)
	}
	sort.Strings(paramNames)
	return path + "?" + strings.Join(paramNames, ",")
}

func queryValueLength(rawURL string) int {
	u, err := url.Parse(rawURL)
	if err != nil {
		return 0
	}
	totalLen := 0
	for _, vals := range u.Query() {
		for _, v := range vals {
			totalLen += len(v)
		}
	}
	return totalLen
}

func dedupBySignature(urls []string) []string {
	type sigEntry struct {
		bestURL string
		bestLen int
		order   int
	}
	sigMap := make(map[string]*sigEntry)
	var orderCounter int

	for _, u := range urls {
		sig := urlSignature(u)
		valLen := queryValueLength(u)

		if entry, exists := sigMap[sig]; exists {
			if valLen > entry.bestLen {
				entry.bestURL = u
				entry.bestLen = valLen
			}
		} else {
			sigMap[sig] = &sigEntry{
				bestURL: u,
				bestLen: valLen,
				order:   orderCounter,
			}
			orderCounter++
		}
	}

	orderedSigs := make([]*sigEntry, 0, len(sigMap))
	for _, entry := range sigMap {
		orderedSigs = append(orderedSigs, entry)
	}
	sort.Slice(orderedSigs, func(i, j int) bool {
		return orderedSigs[i].order < orderedSigs[j].order
	})

	result := make([]string, len(orderedSigs))
	for i, entry := range orderedSigs {
		result[i] = entry.bestURL
	}
	return result
}

func main() {
	urlFile := flag.String("l", "", "URL list file")
	singleURL := flag.String("u", "", "Single target URL")
	flag.StringVar(&outputDir, "o", "./output", "Output directory")
	flag.StringVar(&paramFile, "p", "", "Parameter file")
	flag.StringVar(&techFlag, "tech", "", "Comma-separated list of technologies")
	flag.BoolVar(&forceAll, "force-all", false, "Disable tech-aware skipping logic")
	flag.IntVar(&concurrency, "c", 10, "x9 concurrency")
	flag.IntVar(&workers, "w", 3, "Parallel workers (DOM/headless pipeline concurrency)")
	flag.IntVar(&fastWorkers, "fast-workers", 15, "Fast HTTP-reflection pipeline concurrency")
	flag.IntVar(&maxURLsPerTarget, "max-urls", 50, "Max URLs per target")
	flag.BoolVar(&allowWildcards, "allow-wildcards", false, "Allow wildcard URLs")
	flag.BoolVar(&skipSPA, "skip-spa", true, "Skip SPA detection (if true, do not check for SPA)")
	flag.IntVar(&phase, "phase", 4, "Pipeline phase to stop at (2, 3, or 4)")
	flag.BoolVar(&domScanEnabled, "dom-scan", false, "Enable DOM/headless sink checks via dom_sink_checker (slow; off by default)")

	rateLimitFlag := flag.Float64("rate", 1.0, "Requests per second per host")
	hcIntervalFlag := flag.Duration("hc-interval", 5*time.Minute, "Proxy health-check interval")
	hcTimeoutFlag := flag.Duration("hc-timeout", 5*time.Second, "Proxy health-check timeout")
	runCmdTimeoutFlag := flag.Duration("cmd-timeout", 5*time.Minute, "Hard timeout for external subprocess calls (dom_sink_checker, x9, curl_reflect_checker)")
	flag.Parse()
	runCommandTimeout = *runCmdTimeoutFlag
	ratelimit.Init(ratelimit.Config{
		ReqPerSec:           *rateLimitFlag,
		HealthCheckInterval: *hcIntervalFlag,
		HealthCheckTimeout:  *hcTimeoutFlag,
	})

	_ = ratelimit.LoadProxies("proxies.txt")
	var err error
	repLogger, err = reporter.NewLogger("results/raw_findings.jsonl")
	if err != nil {
		logLine("ERROR", X_red, "reporter init failed: %v", err)
		os.Exit(1)
	}

	if _, err := exec.LookPath("./dom_sink_checker"); err == nil {
		domSinkCheckerExists = true
	} else {
		logLine("WARN", X_yellow, "dom_sink_checker not found or not executable — DOM phases will be skipped")
	}

	if _, err := exec.LookPath("./curl_reflect_checker"); err == nil {
		curlCheckerExists = true
	} else {
		logLine("WARN", X_yellow, "curl_reflect_checker not found or not executable — GET/JSON reflection checks will be skipped")
	}

	loadEnv()
	tg = newTelegram()
	os.MkdirAll(outputDir, 0755)

	var urls []string
	if *singleURL != "" {
		urls = append(urls, *singleURL)
	}

	if *urlFile == "-" {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			if u := strings.TrimSpace(scanner.Text()); u != "" {
				urls = append(urls, u)
			}
		}
	} else if *urlFile != "" {
		file, _ := os.Open(*urlFile)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if u := strings.TrimSpace(scanner.Text()); u != "" {
				urls = append(urls, u)
			}
		}
		file.Close()
	}

	if len(urls) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	urls = uniqueStrings(urls)

	var concreteURLs []string
	for _, u := range urls {
		if isConcreteURL(u) {
			concreteURLs = append(concreteURLs, u)
		}
	}
	urls = concreteURLs

	if *singleURL != "" {
		uTarget, _ := url.Parse(*singleURL)
		if uTarget != nil {
			rootDomain := extractRootDomain(uTarget.Hostname())
			var filtered []string
			for _, u := range urls {
				parsed, err := url.Parse(u)
				if err != nil {
					continue
				}
				host := parsed.Hostname()
				if host == rootDomain || strings.HasSuffix(host, "."+rootDomain) {
					filtered = append(filtered, u)
				}
			}
			urls = filtered
		}
	}

	groups := make(map[string][]string)
	for _, u := range urls {
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		root := extractRootDomain(parsed.Hostname())
		groups[root] = append(groups[root], u)
	}

	var finalURLs []string
	for rootDomain, groupUrls := range groups {
		origCount := len(groupUrls)
		deduped := dedupBySignature(groupUrls)
		dedupCount := len(deduped)

		logLine("DEDUP", X_cyan, "%s: %d URLs -> %d unique signatures (dropped %d)", rootDomain, origCount, dedupCount, origCount-dedupCount)

		groupUrls = deduped

		sort.SliceStable(groupUrls, func(i, j int) bool {
			pi, _ := url.Parse(groupUrls[i])
			pj, _ := url.Parse(groupUrls[j])
			hasQi := pi != nil && len(pi.RawQuery) > 0
			hasQj := pj != nil && len(pj.RawQuery) > 0
			return hasQi && !hasQj
		})

		if maxURLsPerTarget > 0 && len(groupUrls) > maxURLsPerTarget {
			groupUrls = groupUrls[:maxURLsPerTarget]
		}
		finalURLs = append(finalURLs, groupUrls...)
	}
	urls = finalURLs

	allCrawledURLs = append(allCrawledURLs, urls...)

	fastSem := make(chan struct{}, fastWorkers)
	domSem := make(chan struct{}, workers)
	var fastWg sync.WaitGroup
	var domWg sync.WaitGroup
	artifactsChan := make(chan ProbeArtifacts, len(urls))
	dispatcherDone := make(chan struct{})

	go func() {
		for art := range artifactsChan {
			domWg.Add(1)
			domSem <- struct{}{}
			go func(a ProbeArtifacts) {
				defer domWg.Done()
				defer func() { <-domSem }()
				defer func() {
					if r := recover(); r != nil {
						logLine("ERROR", X_red, "panic processing DOM stage for %s: %v", a.TargetURL, r)
					}
				}()
				processURLDom(a)
			}(art)
		}
		close(dispatcherDone)
	}()

	for i, u := range urls {
		fastWg.Add(1)
		fastSem <- struct{}{}
		go func(target string, idx int) {
			defer fastWg.Done()
			defer func() { <-fastSem }()
			defer func() {
				if r := recover(); r != nil {
					logLine("ERROR", X_red, "panic processing %s: %v", target, r)
				}
			}()
			art := processURLFast(target, idx+1, len(urls))
			if art.Skip {
				return
			}
			artifactsChan <- art
		}(u, i)
	}
	fastWg.Wait()
	close(artifactsChan)
	<-dispatcherDone
	domWg.Wait()

	if phase == 3 {
		triageMu.Lock()
		if len(triageEntries) > 0 {
			summaryPath := filepath.Join(outputDir, "triage_summary.txt")
			f, err := os.Create(summaryPath)
			if err == nil {
				for _, entry := range triageEntries {
					if entry.ParamsCount > 0 || entry.DomCount > 0 {
						fmt.Fprintf(f, "%s | params: %d | dom: %d | headers: %d\n",
							entry.TargetURL, entry.ParamsCount, entry.DomCount, entry.HeadersCount)
					}
				}
				f.Close()
				logLine("INFO", X_green, "Triage summary written to %s", summaryPath)
			} else {
				logLine("ERROR", X_red, "Failed to write triage summary: %v", err)
			}
		}
		triageMu.Unlock()
	}

	finalIn := filepath.Join(outputDir, "all_crawled_discovery.txt")
	os.WriteFile(finalIn, []byte(strings.Join(uniqueStrings(allCrawledURLs), "\n")), 0644)

	if !curlCheckerExists {
		logLine("WARN", X_yellow, "curl_reflect_checker not available, skipping Global Second-Order Check")
	} else {
		res, err := runCommand("./curl_reflect_checker", "-l", finalIn, "-xss")
		if err != nil {
			logLine("CURLCHECK-ERR", X_red, "Global Second-Order Check: curl_reflect_checker exited with error: %v", err)
		} else if res == "" {
			logLine("CURLCHECK-EMPTY", X_yellow, "Global Second-Order Check: curl_reflect_checker ran but returned no output")
		}

		if res != "" {
			reflectedURLs := extractReflectedURLsFromCurl(res)
			if len(reflectedURLs) > 0 {
				soReport := VulnerabilityReport{URL: "Global Second-Order Check"}
				aggregateCurlFindings(&soReport, reflectedURLs, "get", "Global Second-Order Check")
				if soReport.HasVulns() {
					tg.notify(soReport)
				}
			}
		}
	}

	wafCount := atomic.LoadInt64(&wafChallengeDetected)
	if wafCount > 0 {
		fmt.Printf("\n%s[DONE]%s Pipeline Complete. (WAF Challenges Detected: %d)\n", X_green, X_reset, wafCount)
	} else {
		fmt.Printf("\n%s[DONE]%s Pipeline Complete.\n", X_green, X_reset)
	}
}
