// Package cookiebomb detects "Cookie Bomb" reflection vulnerabilities.
// This occurs when a tracking query parameter's value is written verbatim into
// a Set-Cookie response header. By inflating the parameter's size, an attacker
// can force the server to set an oversized cookie, potentially exceeding server
// header limits on subsequent requests and causing a self-DoS (HTTP 400/414).
package cookiebomb

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"reconpipeline/pkg/ratelimit"
)

const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
	"AppleWebKit/537.36 (KHTML, like Gecko) " +
	"Chrome/126.0.0.0 Safari/537.36"

type Finding struct {
	Parameter  string
	CookieName string
	Confidence string
	Variant    string
}

var candidateParams = []string{
	"gclid", "dclid", "msclkid", "fbclid", "ttclid", "twclid",
	"utm_source", "utm_medium", "utm_campaign", "utm_term",
	"utm_content", "gbraid", "wbraid", "igshid", "yclid",
}

// CheckCookieBomb probes the target URL for Set-Cookie header reflection.
func CheckCookieBomb(targetURL string) []Finding {
	var findings []Finding

	parsedURL, err := url.Parse(targetURL)
	if err != nil || parsedURL.Hostname() == "" {
		return findings
	}

	for _, param := range candidateParams {
		// Stage 1: 50-character probe
		probe1 := generateRandomString(50)
		testURL1 := appendQueryParam(parsedURL, param, probe1)
		
		ratelimit.Acquire(targetURL)
		_, respHeaders1, _, err1 := curlRequestAttempt(testURL1, "GET", nil, 15)
		if err1 != nil {
			continue
		}

		setCookie1 := respHeaders1["set-cookie"]
		if !strings.Contains(setCookie1, probe1) {
			continue // No reflection in Stage 1
		}

		cookieName := extractCookieName(setCookie1, probe1)

		// Stage 2: 500-character probe for proportional growth check
		probe2 := generateRandomString(500)
		testURL2 := appendQueryParam(parsedURL, param, probe2)

		ratelimit.Acquire(targetURL)
		_, respHeaders2, _, err2 := curlRequestAttempt(testURL2, "GET", nil, 15)
		if err2 != nil {
			continue
		}

		setCookie2 := respHeaders2["set-cookie"]
		
		confidence := "MEDIUM"
		variant := "partial_reflection"

		if strings.Contains(setCookie2, probe2) {
			confidence = "HIGH"
			variant = "raw_reflection"
		}
		
		// LOW confidence is reserved as a placeholder for parameter-accepted-but-not-set
		// cases, allowing future multi-parameter combination logic.

		findings = append(findings, Finding{
			Parameter:  param,
			CookieName: cookieName,
			Confidence: confidence,
			Variant:    variant,
		})
	}

	return findings
}

func appendQueryParam(base *url.URL, key, value string) string {
	u := *base
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}

func generateRandomString(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

func extractCookieName(headerVal, probe string) string {
	cookies := strings.Split(headerVal, "\n")
	for _, c := range cookies {
		if strings.Contains(c, probe) {
			parts := strings.SplitN(c, "=", 2)
			if len(parts) > 0 {
				return strings.TrimSpace(parts[0])
			}
		}
	}
	return "unknown"
}

// curlRequestAttempt mirrors the core curl-exec and header parsing pattern from corscheck.go.
func curlRequestAttempt(targetURL, method string, headers map[string]string, timeout int) (statusCode int, respHeaders map[string]string, respBody []byte, err error) {
	args := []string{
		"-s", "-L", "-i",
		"--max-time", strconv.Itoa(timeout),
		"-A", userAgent,
		"-w", "\\nHTTPSTATUS:%{http_code}",
	}

	if method == "HEAD" {
		args = append(args, "-I")
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

	rawOutput := stdout[:idx]
	respHeaders = make(map[string]string)
	offset := 0
	for {
		for offset < len(rawOutput) && (rawOutput[offset] == '\r' || rawOutput[offset] == '\n') {
			offset++
		}
		if offset >= len(rawOutput) || !bytes.HasPrefix(rawOutput[offset:], []byte("HTTP/")) {
			break
		}
		end := bytes.Index(rawOutput[offset:], []byte("\r\n\r\n"))
		if end == -1 {
			break
		}
		block := string(rawOutput[offset : offset+end])
		lines := strings.Split(block, "\n")
		
		respHeaders = make(map[string]string)
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if sepIdx := strings.Index(line, ":"); sepIdx > 0 {
				key := strings.ToLower(strings.TrimSpace(line[:sepIdx]))
				val := strings.TrimSpace(line[sepIdx+1:])
				// Aggregate Set-Cookie headers using newline to preserve multiples
				if key == "set-cookie" && respHeaders[key] != "" {
					respHeaders[key] += "\n" + val
				} else {
					respHeaders[key] = val
				}
			}
		}
		offset += end + 4
	}
	respBody = rawOutput[offset:]

	return statusCode, respHeaders, respBody, nil
}