// FILE: xssniper.go — REFACTORED LOGGING, TECH-AWARE ROUTING & JS RISK DETECTION
// Changes:
// - Removed IsLegacyServerRendered logic and legacy framework assumptions.
// - Added hasClientSideJSRisk() to perform a lightweight GET and check for <script> tags.
// - Changed DOM check skipping logic to only trigger when NO JavaScript is present in the DOM.
// - Retained SPA logic for skipping Header Injection.

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"reconpipeline/pkg/ratelimit"
	"reconpipeline/pkg/reporter"
)

var repLogger *reporter.Logger

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

// hasClientSideJSRisk performs a quick GET request to check if the target has ANY scripts.
// If it fails or times out, it conservatively returns true (assume JS exists).
func hasClientSideJSRisk(targetURL string) bool {
	ratelimit.Acquire(targetURL)
	client := ratelimit.GetHTTPClient(targetURL)
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return true // conservative fallback
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; xssniper)")
	
	resp, err := client.Do(req)
	if err != nil {
		return true
	}
	defer resp.Body.Close()
	
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return true
	}
	
	bodyLower := strings.ToLower(string(bodyBytes))
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
	URL             string          `json:"url"`
	QueryParameters []Vulnerability `json:"query_parameters,omitempty"`
	Headers         []Vulnerability `json:"headers,omitempty"`
	JSONBody        []Vulnerability `json:"json_body,omitempty"`
	DOM             []Vulnerability `json:"dom,omitempty"`
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
	default: // "possible"
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
}

func (r *VulnerabilityReport) HasVulns() bool {
	return len(r.QueryParameters) > 0 || len(r.Headers) > 0 || len(r.JSONBody) > 0 || len(r.DOM) > 0
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
	client := ratelimit.GetHTTPClient(targetURL)
	var req *http.Request
	var err error

	if method == "POST" {
		req, err = http.NewRequest("POST", targetURL, strings.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	} else {
		req, err = http.NewRequest("GET", targetURL, nil)
	}

	if err != nil {
		return false
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
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
	renderSection("JSON Body", report.JSONBody)
	renderSection("DOM", report.DOM)
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

// Helper to send the formatted Telegram message using the existing envelope configuration
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

	// 1. Terminal Output and File Write (Always triggers for any finding)
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

	// 2. Evaluate Findings for Telegram Push
	if tg == nil {
		return
	}

	hasConfirmed := false
	hasValidCandidate := false
	totalVulns := 0
	noisyDOMVulns := 0

	checkList := [][]Vulnerability{report.QueryParameters, report.Headers, report.JSONBody, report.DOM}
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

	// If all findings are known-noisy DOM false positives, suppress Telegram notification completely.
	if totalVulns > 0 && totalVulns == noisyDOMVulns {
		return
	}

	ts := time.Now().Format("2006-01-02 15:04:05")

	// 3. Dispatch appropriate message types
	if hasConfirmed {
		// PATH A: High-Urgency Confirmed Finding
		var sb strings.Builder
		sb.WriteString("🚨 <b>CONFIRMED XSS</b>\n\n")
		sb.WriteString(fmt.Sprintf("🎯 <b>Target:</b> <code>%s</code>\n", escapeHTML(report.URL)))
		sb.WriteString(fmt.Sprintf("📅 <b>Time:</b> %s\n\n", ts))
		sb.WriteString(fmt.Sprintf("<pre>%s</pre>", escapeHTML(string(reportJSON))))

		tg.sendMessage(sb.String())

	} else if hasValidCandidate {
		// PATH B: Lower-key Candidate Finding (Likely/Possible)
		// Ensure we only spam this candidate summary once per target URL per run.
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
	mu                   sync.Mutex
	tg                   *Telegram
	allCrawledURLs       []string
	maxURLsPerTarget     int
	allowWildcards       bool
	processedTargets     int64
	vulnerableTargets    int64
	vulnerableMap        sync.Map
	workerLock           sync.Map
	vulnerableMap     sync.Map
	workerLock        sync.Map
	candidateNotified sync.Map
	nucleiExists         bool
	domSinkCheckerExists bool
	skipSPA              bool

	consecutiveDead int64

	phase int

	reX9       = regexp.MustCompile(`x9(?:canary)?[a-z]*`)
	rePayload  = regexp.MustCompile(`\[(?:"([^"]+)"|([^"\]]+))\]$`)
	reANSI     = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	reCleaning = regexp.MustCompile(`\s*\["0m"\]\s*`)

	triageMu      sync.Mutex
	triageEntries []TriageEntry
)

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

func isTargetAlive(targetURL string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ratelimit.Acquire(targetURL)
	client := ratelimit.GetHTTPClient(targetURL)
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	}
	
	u, err := url.Parse(targetURL)
	if err != nil {
		return false
	}
	u.Fragment = ""
	checkURL := u.String()

	req, _ := http.NewRequestWithContext(ctx, "HEAD", checkURL, nil)
	resp, err := client.Do(req)

	if err != nil {
		ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel2()
		reqGET, _ := http.NewRequestWithContext(ctx2, "GET", checkURL, nil)
		resp, err = client.Do(reqGET)
		if err != nil {
			return false
		}
	} else {
		defer resp.Body.Close()
		if resp.StatusCode < 400 || resp.StatusCode == 401 || resp.StatusCode == 403 {
			return true
		}
		if resp.StatusCode >= 404 && resp.StatusCode != 405 {
			return false
		}
		reqGET, _ := http.NewRequestWithContext(ctx, "GET", checkURL, nil)
		resp, err = client.Do(reqGET)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
	}

	return resp.StatusCode < 500
}

func checkConnectivity() bool {
	conn, err := net.DialTimeout("tcp", "8.8.8.8:53", 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func runCommand(name string, args ...string) (string, error) {
	if name == "nuclei" && !nucleiExists {
		return "", nil
	}
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
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

// ── SPA Detection ────────────────────────────────────────────────────────────

func isSPA(targetURL string) bool {
	ratelimit.Acquire(targetURL)
	client := ratelimit.GetHTTPClient(targetURL)
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; xssniper)")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	body := string(bodyBytes)

	markers := []string{
		`<div id="root"`,
		`<div id="app"`,
		`__NEXT_DATA__`,
		`window.__INITIAL_STATE__`,
		`ReactDOM.render`,
		`ng-version=`,
		`data-reactroot`,
	}
	for _, m := range markers {
		if strings.Contains(body, m) {
			return true
		}
	}

	reScript := regexp.MustCompile(`(?s)<script[^>]*>.*?</script>`)
	reStyle := regexp.MustCompile(`(?s)<style[^>]*>.*?</style>`)
	clean := reScript.ReplaceAllString(body, "")
	clean = reStyle.ReplaceAllString(clean, "")
	reTag := regexp.MustCompile(`<[^>]*>`)
	text := reTag.ReplaceAllString(clean, " ")
	visibleCount := 0
	for _, ch := range text {
		if !unicode.IsSpace(ch) {
			visibleCount++
		}
	}
	if visibleCount < 500 {
		return true
	}

	xPoweredBy := resp.Header.Get("x-powered-by")
	if strings.Contains(strings.ToLower(xPoweredBy), "next.js") && visibleCount < 500 {
		return true
	}
	if strings.Contains(strings.ToLower(xPoweredBy), "express") && visibleCount < 500 {
		return true
	}

	return false
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
	u.RawQuery = q.Encode()
	finalURL := u.String()

	ratelimit.Acquire(finalURL)
	client := ratelimit.GetHTTPClient(finalURL)
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 2 {
			return http.ErrUseLastResponse
		}
		return nil
	}
	
	req, err := http.NewRequest("GET", finalURL, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	body := string(bodyBytes)

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

func confirmParameter(targetURL, phase, name string) (bool, []string) {
	prefix := "x9" + randomString(3)
	breakChars := []string{"'", "\"", "`", "<", ";", "{{"}
	var confirmed []string

	for _, bc := range breakChars {
		p := prefix + bc
		method := "GET"
		headers := make(map[string]string)
		body := ""
		finalURL := targetURL

		u, err := url.Parse(targetURL)
		if err != nil {
			continue
		}

		switch phase {
		case "get":
			q := u.Query()
			q.Set(name, p)
			u.RawQuery = q.Encode()
			finalURL = u.String()
		case "header":
			headers[name] = p
		case "json":
			method = "POST"
			data := make(map[string]interface{})
			data[name] = p
			b, _ := json.Marshal(data)
			body = string(b)
		}

		if reflectionExists(finalURL, method, headers, body, p) {
			confirmed = append(confirmed, p)
		}
	}
	return len(confirmed) > 0, confirmed
}

func reflectionExists(targetURL, method string, headers map[string]string, body, payload string) bool {
	// ۱. گرفتن اجازه (Token) قبل از شروع هر درخواست شبکه برای این دامنه
	ratelimit.Acquire(targetURL)

	// ۲. استفاده از کلاینت مدیریت‌شده (همراه با Proxy چرخشی و Timeout)
	client := ratelimit.GetHTTPClient(targetURL)

	var req *http.Request
	var err error
	if method == "POST" {
		req, err = http.NewRequest("POST", targetURL, strings.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	} else {
		req, err = http.NewRequest("GET", targetURL, nil)
	}
	if err != nil || req == nil {
		return false
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	b, _ := io.ReadAll(resp.Body)
	return strings.Contains(string(b), payload)
}

func checkHeaderReflection(targetURL, headerName, headerValue string) bool {
	headers := map[string]string{headerName: headerValue}
	return reflectionExists(targetURL, "GET", headers, "", headerValue)
}

// extractBreakChars returns unique break characters found in a canary value.
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

// ── processURL ──────────────────────────────────────────────────────────────

func processURL(targetURL string, index, total int) {
	uParsed, err := url.Parse(targetURL)
	if err != nil || uParsed == nil {
		logLine("SKIP", X_yellow, "unparseable URL, skipping: %s", targetURL)
		return
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
		return
	}

	atomic.AddInt64(&processedTargets, 1)
	currProcessed := atomic.LoadInt64(&processedTargets)
	currVulns := atomic.LoadInt64(&vulnerableTargets)

	logLine("TARGET", X_white, "[%d/%d | Vulns: %d] %s", currProcessed, total, currVulns, targetURL)

	if !skipSPA && isSPA(targetURL) {
		logLine("SKIP", X_yellow, "SPA/React detected, skipping heavy scan for %s", targetURL)
		return
	}

	if isGenericReflector(targetURL) {
		logLine("SKIP", X_yellow, "Generic reflector detected, skipping %s", targetURL)
		return
	}

	// Tech-Aware Profile Classification (for Header Injection only)
	techListStr := strings.Split(techFlag, ",")
	profile := classifyTechProfile(techListStr)

	report := VulnerabilityReport{URL: targetURL}

	// Phase 2: Canary Probe
	probeInput := filepath.Join(outputDir, safeName(targetURL)+"-probe-in.txt")
	os.WriteFile(probeInput, []byte(targetURL), 0644)

	probeOutputBase := filepath.Join(outputDir, safeName(targetURL)+"-probe-out")

	args := []string{"-probe", "-json", "-headers", "-dom"}
	if uParsed.RawQuery != "" {
		args = append(args, "-strict")
	}
	args = append(args, "-i", probeInput, "-o", probeOutputBase)
	runCommand("./x9", args...)

	// Phase 2: Canary Probing - DOM query params
	domQueryProbeFile := filepath.Join(outputDir, safeName(targetURL)+"-dom-query-probe.txt")
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
		return
	}

	// Phase 3: Filter Vulnerable Parameters
	targetAlive := isTargetAlive(targetURL)
	var hasJS bool
	if targetAlive {
		hasJS = hasClientSideJSRisk(targetURL)
		atomic.StoreInt64(&consecutiveDead, 0)
	} else {
		newCount := atomic.AddInt64(&consecutiveDead, 1)
		if newCount%5 == 0 {
			for !checkConnectivity() {
				logLine("WARN", X_yellow, "Network connectivity lost — pausing scan for 30 seconds")
				time.Sleep(30 * time.Second)
			}
		}
	}

	probeFiles := map[string]string{
		probeOutputBase + ".get":        "get",
		probeOutputBase + ".json":       "json",
		probeOutputBase + ".header":     "header",
		probeOutputBase + ".dom.canary": "dom",
	}

	p3Findings := make(map[string][]string)
	candidateHeaders := []string{}

	domProbeSkippedAll := false

	for pf, probePhase := range probeFiles {
		if _, err := os.Stat(pf); err == nil {
			
			// TECH-AWARE: Skip Header parsing logic if SPA
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

			} else if probePhase == "dom" {
				// TECH-AWARE: Skip DOM sink if absolutely no JS exists on page
				if !hasJS && !forceAll {
					logLine("SKIP-NOJS", X_cyan, "Skipping DOM checks for %s: no <script> tags detected in page", targetURL)
					domProbeSkippedAll = true
					continue
				}

				if !targetAlive {
					domProbeSkippedAll = true
					continue
				}

				if domSinkCheckerExists {
					res, _ := runCommand("./dom_sink_checker", "-l", pf)
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
			} else {
				res, _ := runCommand("nuclei", "-l", pf, "-t", canaryTemplate, "-silent")
				p3Findings[probePhase] = append(p3Findings[probePhase], extractURLsFromNuclei(res)...)
			}
		}
	}

	// DOM query probe
	if _, err := os.Stat(domQueryProbeFile); err == nil {
		if !hasJS && !forceAll {
			logLine("SKIP-NOJS", X_cyan, "Skipping DOM query sink checker for %s: no <script> tags detected in page", targetURL)
			if !targetAlive {
				domProbeSkippedAll = true
			}
		} else if !targetAlive {
			domProbeSkippedAll = true
		} else if domSinkCheckerExists {
			res, _ := runCommand("./dom_sink_checker", "-l", domQueryProbeFile)
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

	if domProbeSkippedAll && (fileExists(probeOutputBase+".dom.canary") || fileExists(domQueryProbeFile)) {
		logLine("DEAD", X_yellow, "%s", targetURL)
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

	domCount := len(p3Findings["dom"])
	headers := candidateHeaders
	sort.Strings(headers)

	if len(getParamSet) > 0 || domCount > 0 || len(headers) > 0 {
		paramsStr := strings.Join(getParams, ", ")
		if paramsStr == "" {
			paramsStr = "none"
		}
		headersStr := strings.Join(headers, ", ")
		if headersStr == "" {
			headersStr = "none"
		}
		logLine("HIT", X_green, "%s → params: %s | dom: %d | headers: %s", targetURL, paramsStr, domCount, headersStr)
	} else {
		logLine("CLEAN", X_gray, "%s", targetURL)
	}

	if phase == 3 {
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
			for _, u := range p3Findings["get"] {
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
		if domCount == 0 {
			triageContent.WriteString("none\n\n")
		} else {
			for _, line := range p3Findings["dom"] {
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

		return
	}

	if len(p3Findings) == 0 && len(candidateHeaders) == 0 {
		return
	}

	// Phase 4b: Triage & Context Confirmation
	confirmedParams := make(map[string]map[string]bool)
	for p := range p3Findings {
		confirmedParams[p] = make(map[string]bool)
	}

	for probePhase, urls := range p3Findings {
		if probePhase == "dom" {
			continue
		}
		tempRep := VulnerabilityReport{URL: targetURL}
		dummy := ""
		for _, u := range urls {
			dummy += "[canary] [info] " + u + " [x9canary]\n"
		}
		tempRep.aggregateFindings(dummy, probePhase)

		var vList *[]Vulnerability
		switch probePhase {
		case "get":
			vList = &tempRep.QueryParameters
		case "json":
			vList = &tempRep.JSONBody
		}

		if vList != nil {
			for _, v := range *vList {
				if ok, p := confirmParameter(targetURL, probePhase, v.Name); ok {
					v.Confirmed = true
					v.Severity = "confirmed"
					v.Payloads = p
					confirmedParams[probePhase][v.Name] = true
				}
			}
		}
	}

	for _, headerName := range candidateHeaders {
		if ok, payloads := confirmParameter(targetURL, "header", headerName); ok {
			v := Vulnerability{
				Name:      headerName,
				Severity:  "confirmed",
				Confirmed: true,
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

	// Phase 4: Heavy Attack
	httpAtkUrls := []string{}
	for probePhase, urls := range p3Findings {
		if probePhase == "dom" {
			continue
		}
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
			if findings, _ := runCommand("nuclei", "-l", finalX9Base+ext, "-t", nucleiTemplate, "-silent"); findings != "" {
				report.aggregateFindings(findings, ph)
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

	// Phase 4 DOM: fragment URLs
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
				if dom, _ := runCommand("./dom_sink_checker", "-xss", "-l", finalX9Base+".dom.attack", "-timeout", "300"); dom != "" {
					report.aggregateFindings(dom, "dom_confirmed")
				}
			}
		}
	}

	for _, line := range p3Findings["dom"] {
		var domOut DomSinkOutput
		if err := json.Unmarshal([]byte(line), &domOut); err != nil {
			continue
		}
		report.processDomJson(domOut, "dom")
	}

	// Phase 4c: DOM Query Attack
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
				dom, _ := runCommand("./dom_sink_checker", "-xss", "-l", finalX9Base+".get", "-timeout", "300")
				if dom != "" {
					report.aggregateFindings(dom, "dom_confirmed")
				}
			}
		}
	}

	if report.HasVulns() {
		tg.notify(report)
	}
	logReportFindings(&report)
}

// ── Helper: safe name for file naming ──────────────────────────────────────

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

// ── main ────────────────────────────────────────────────────────────────────

func main() {
	urlFile := flag.String("l", "", "URL list file")
	singleURL := flag.String("u", "", "Single target URL")
	flag.StringVar(&outputDir, "o", "./output", "Output directory")
	flag.StringVar(&nucleiTemplate, "t", "xss_template_v2.yaml", "Reflection template")
	flag.StringVar(&domTemplate, "dom", "dom_xss.yaml", "DOM template")
	flag.StringVar(&canaryTemplate, "canary", "canary_matcher.yaml", "Canary template")
	flag.StringVar(&paramFile, "p", "", "Parameter file")
	flag.StringVar(&techFlag, "tech", "", "Comma-separated list of technologies")
	flag.BoolVar(&forceAll, "force-all", false, "Disable tech-aware skipping logic")
	flag.IntVar(&concurrency, "c", 10, "x9 concurrency")
	flag.IntVar(&workers, "w", 3, "Parallel workers")
	flag.IntVar(&maxURLsPerTarget, "max-urls", 50, "Max URLs per target")
	flag.BoolVar(&allowWildcards, "allow-wildcards", false, "Allow wildcard URLs")
	flag.BoolVar(&skipSPA, "skip-spa", true, "Skip SPA detection (if true, do not check for SPA)")
	flag.IntVar(&phase, "phase", 4, "Pipeline phase to stop at (2, 3, or 4)")
	flag.Parse()
	ratelimit.StartServer()
    
    // ۲. لود کردن پروکسی‌ها (در صورتی که فایل وجود داشته باشد)
    _ = ratelimit.LoadProxies("proxies.txt")
	var err error
	repLogger, err = reporter.NewLogger("results/raw_findings.jsonl")
	if err != nil {
		logLine("ERROR", X_red, "reporter init failed: %v", err)
		os.Exit(1)
	}
	if _, err := exec.LookPath("nuclei"); err == nil {
		nucleiExists = true
	} else {
		logLine("WARN", X_yellow, "Nuclei not found in PATH. Skipping nuclei phases.")
	}

	if _, err := exec.LookPath("./dom_sink_checker"); err == nil {
		domSinkCheckerExists = true
	} else {
		logLine("WARN", X_yellow, "dom_sink_checker not found or not executable — DOM phases will be skipped")
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
	for _, groupUrls := range groups {
		sort.Slice(groupUrls, func(i, j int) bool {
			pi, _ := url.Parse(groupUrls[i])
			pj, _ := url.Parse(groupUrls[j])
			hasQi := pi != nil && len(pi.RawQuery) > 0
			hasQj := pj != nil && len(pj.RawQuery) > 0
			if hasQi != hasQj {
				return hasQi
			}
			return len(groupUrls[i]) < len(groupUrls[j])
		})

		if maxURLsPerTarget > 0 && len(groupUrls) > maxURLsPerTarget {
			groupUrls = groupUrls[:maxURLsPerTarget]
		}
		finalURLs = append(finalURLs, groupUrls...)
	}
	urls = finalURLs

	allCrawledURLs = append(allCrawledURLs, urls...)

	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, u := range urls {
		wg.Add(1)
		sem <- struct{}{}
		go func(target string, idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					logLine("ERROR", X_red, "panic processing %s: %v", target, r)
				}
			}()
			processURL(target, idx+1, len(urls))
		}(u, i)
	}
	wg.Wait()

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
	if so, _ := runCommand("nuclei", "-l", finalIn, "-t", nucleiTemplate, "-silent"); so != "" {
		soReport := VulnerabilityReport{URL: "Global Second-Order Check"}
		soReport.aggregateFindings(so, "get")
		if soReport.HasVulns() {
			tg.notify(soReport)
		}
	}
	fmt.Printf("\n%s[DONE]%s Pipeline Complete.\n", X_green, X_reset)
}
