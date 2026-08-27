package corscheck

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"reconpipeline/pkg/ratelimit"
)

// Shared User-Agent constant mirroring xssniper.go
const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
	"AppleWebKit/537.36 (KHTML, like Gecko) " +
	"Chrome/126.0.0.0 Safari/537.36"

type Finding struct {
	Origin           string // the Origin value we sent
	ReflectedACAO    string // the Access-Control-Allow-Origin value received
	AllowCredentials bool   // whether Access-Control-Allow-Credentials: true was present
	Confidence       string // "HIGH", "MEDIUM", or "LOW"
	Variant          string // short label: "exact_reflect", "null_origin", "subdomain_bypass", "prefix_bypass", "suffix_bypass"
}

// CheckCORS probes the target URL for CORS misconfigurations using various Origin spoofing techniques.
func CheckCORS(targetURL string) []Finding {
	var findings []Finding

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[corscheck] Error parsing URL %q: %v\n", targetURL, err)
		return findings
	}

	hostname := parsedURL.Hostname()
	if hostname == "" {
		fmt.Fprintf(os.Stderr, "[corscheck] Skipped (no hostname): %s\n", targetURL)
		return findings
	}

	const attacker = "evil-corstest.com"

	variants := map[string]string{
		"exact_reflect":    "https://" + attacker,
		"null_origin":      "null",
		"subdomain_bypass": "https://" + hostname + "." + attacker,
		"prefix_bypass":    "https://" + attacker + hostname,
		"suffix_bypass":    "https://" + attacker + "." + hostname,

		// --- NEW: userinfo / double-scheme / backslash-normalization bypasses ---
		// Some parsers (Node's legacy url.parse, some Java/older browser URL
		// implementations) treat the segment BEFORE '@' as userinfo and only
		// look at what's AFTER '@' as the host, or mis-handle a second
		// "scheme:" / backslash as a path/host separator equivalent to '/'.
		"userinfo_bypass":             "https://" + hostname + "@" + attacker,
		"double_scheme_www":           "https:https://www." + hostname,
		"double_scheme_path_bypass":   "https:https://" + attacker + "/" + hostname,
		"double_scheme_query_bypass":  "https:https://" + attacker + "?" + hostname,
		"double_scheme_dot_backslash": "https:https://" + attacker + `\.` + hostname,
		"double_scheme_at_backslash":  "https:https://" + attacker + `\@www.` + hostname,
		"backslash_dot_bypass":        "https://" + attacker + `\.` + hostname,
		"backslash_at_bypass":         "https://" + attacker + `\@www.` + hostname,
	}

	for variant, originValue := range variants {
		// Respect the global rate limit per host exactly like the rest of the codebase
		ratelimit.Acquire(targetURL)

		headers := map[string]string{
			"Origin": originValue,
		}

		// Single execution (15s timeout), no retries for CORS checks
		_, respHeaders, _, err := curlRequestAttempt(targetURL, "GET", headers, 15)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[corscheck] Curl error on %s (variant: %s): %v\n", targetURL, variant, err)
			continue
		}

		acao := respHeaders["access-control-allow-origin"]
		acac := respHeaders["access-control-allow-credentials"]

		// Skip if empty, wildcard, or does not reflect our exact spoofed origin
		if acao == "" || acao == "*" || acao != originValue {
			continue
		}

		allowCreds := strings.ToLower(acac) == "true"
		confidence := "LOW" // Default for reflection without credentials

		if allowCreds {
			confidence = "HIGH"
		}

		findings = append(findings, Finding{
			Origin:           originValue,
			ReflectedACAO:    acao,
			AllowCredentials: allowCreds,
			Confidence:       confidence,
			Variant:          variant,
		})
	}

	return findings
}

// curlRequestAttempt mirrors the core curl-exec and header parsing pattern from xssniper.go
// bypassing net/http to maintain JA3-evasion consistency.
func curlRequestAttempt(targetURL, method string, headers map[string]string, timeout int) (statusCode int, respHeaders map[string]string, respBody []byte, err error) {
	args := []string{
		"-s",
		"-L",
		"-i", // Fetch HTTP headers
		"--max-time", strconv.Itoa(timeout),
		"-A", userAgent,
		"-w", "\\nHTTPSTATUS:%{http_code}",
	}

	if method == "HEAD" {
		args = append(args, "-I")
	} else if method != "GET" && method != "" {
		args = append(args, "-X", method)
	}

	// Always append base caching directives alongside custom headers
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

	// Parse headers, respecting redirects just like xssniper.go
	rawOutput := stdout[:idx]
	respHeaders = make(map[string]string)
	offset := 0
	for {
		// Skip empty chars
		for offset < len(rawOutput) && (rawOutput[offset] == '\r' || rawOutput[offset] == '\n') {
			offset++
		}
		if offset >= len(rawOutput) {
			break
		}
		if !bytes.HasPrefix(rawOutput[offset:], []byte("HTTP/")) {
			break
		}
		end := bytes.Index(rawOutput[offset:], []byte("\r\n\r\n"))
		if end == -1 {
			break
		}
		block := string(rawOutput[offset : offset+end])
		lines := strings.Split(block, "\n")
		// Reset map per redirect, leaving only the final headers
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
