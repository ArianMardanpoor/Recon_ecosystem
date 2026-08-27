// curl_reflect_checker.go — standalone canary/break-char reflection detector
// that issues HTTP requests via the curl binary (exec'd) instead of Go's
// net/http, avoiding JA3/TLS fingerprinting by WAFs (F5, Volterra, …).
//
// Behaviour mirrors nuclei's canary_matcher.yaml / xss_template_v2.yaml
// matchers but uses curl (OpenSSL/libcurl TLS stack) so that WAFs that
// block Go's net/http JA3 no longer cause false negatives.
//
// PATCH (retry-on-timeout): some targets take longer than the configured
// --max-time to respond (observed ~7-8s baseline against a live target,
// worse under concurrent worker-pool load). A single curl timeout (exit 28)
// or status 000 used to be silently logged and treated as "no reflection",
// causing false negatives on real, confirmed vulnerabilities. checkURL now
// retries once with a doubled timeout before giving up on a URL.

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"reconpipeline/pkg/reflectctx"
)

var reX9 = regexp.MustCompile(`(?:<b9|['"])?x9(?:canary)?[a-z]*(?:['"\;<{]|\{\{)?`)

// canaryRe — canary_matcher.yaml regex, byte-for-byte identical:
//
//	x9canary[a-z]{3}
var canaryRe = regexp.MustCompile(`x9canary[a-z]{3}`)

// xssRe — xss_template_v2.yaml break-char regex, byte-for-byte identical:
//
//	x9[a-z]{3}['"` + "`" + `\;<{]
var xssRe = regexp.MustCompile(`x9[a-z]{3}['"` + "`" + `\;<{]`)

const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
	"AppleWebKit/537.36 (KHTML, like Gecko) " +
	"Chrome/126.0.0.0 Safari/537.36"

// DomSinkOutput matches the struct used elsewhere in the codebase so
// downstream JSON-line parsing does not need to change.
type DomSinkOutput struct {
	URL        string   `json:"url"`
	Sinks      []string `json:"sinks"`
	StatusCode int      `json:"status_code,omitempty"`
}

type checkOpts struct {
	xssMode bool
	timeout int
	outMu   *sync.Mutex
}

// extractMarkerChar determines the intended breakout character from the x9 payload.
func extractMarkerChar(payload string) (byte, bool) {
	if strings.HasPrefix(payload, "\"") || strings.HasPrefix(payload, "'") {
		return payload[0], true
	}
	if strings.HasPrefix(payload, "<b9") {
		return '<', true
	}
	if len(payload) > 0 {
		last := payload[len(payload)-1]
		if last == '\'' || last == '"' || last == '`' || last == '<' || last == ';' {
			return last, true
		}
		if strings.HasSuffix(payload, "{{") {
			return '{', true
		}
	}
	return 0, false
}

// getDecodedPayload correctly parses the URL and unescapes the parameter values
// before searching for the x9 canary and its breakout markers.
func getDecodedPayload(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err == nil {
		for _, vals := range parsed.Query() {
			for _, v := range vals {
				if match := reX9.FindString(v); match != "" {
					return match
				}
			}
		}
	}

	// Fallback: If not found in query params (e.g., it's in the path or fragment),
	// match against the raw URL and unescape the result.
	rawMatch := reX9.FindString(rawURL)
	if rawMatch != "" {
		if unescaped, err := url.QueryUnescape(rawMatch); err == nil {
			return unescaped
		}
		return rawMatch
	}
	return ""
}

func main() {
	listFile := flag.String("l", "", "input file with one URL per line (use - for stdin)")
	xssMode := flag.Bool("xss", false, "search for break-char pattern instead of plain canary")
	timeout := flag.Int("timeout", 20, "per-request curl timeout in seconds (retried once at 2x on failure)")
	concurrency := flag.Int("c", 5, "number of concurrent curl processes")
	checkLocation := flag.Bool("check-location", false, "check Location header for open-redirect / header injection instead of body reflection (does not follow redirects)")
	flag.Parse()

	if *listFile == "" {
		fmt.Fprintln(os.Stderr, "[ERROR] -l <file> is required (use -l - for stdin)")
		os.Exit(1)
	}

	var input *os.File
	if *listFile == "-" {
		input = os.Stdin
	} else {
		f, err := os.Open(*listFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] failed to open %s: %v\n", *listFile, err)
			os.Exit(1)
		}
		defer f.Close()
		input = f
	}

	c := *concurrency
	if c < 1 {
		c = 1
	}

	var outMu sync.Mutex
	opts := checkOpts{
		xssMode: *xssMode,
		timeout: *timeout,
		outMu:   &outMu,
	}

	// Worker pool — buffered channel + goroutines + WaitGroup,
	// matching the pattern in nice_params.go's processURLFile.
	urls := make(chan string, c*2)
	var wg sync.WaitGroup

	for i := 0; i < c; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range urls {
				if *checkLocation {
					checkLocationHeader(u, opts)
				} else {
					checkURL(u, opts)
				}
			}
		}()
	}

	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		urls <- line
	}
	close(urls)
	wg.Wait()

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] reading input: %v\n", err)
		os.Exit(1)
	}
}

// runCurl is the low-level process-exec helper shared by curlAttempt and
// checkLocationHeader. It builds the common curl invocation (UA, accept
// headers, HTTPSTATUS trailer trick, timeout/context handling) and lets
// callers customize the follow-redirect behavior and extra flags.
func runCurl(rawURL string, timeoutSec int, followRedirects bool, extraArgs ...string) (stdout []byte, err error) {
	args := []string{"-s"}
	if followRedirects {
		args = append(args, "-L")
	}
	args = append(args,
		"--max-time", strconv.Itoa(timeoutSec),
		"-A", userAgent,
		"-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
		"-H", "Accept-Language: en-US,en;q=0.9",
	)
	args = append(args, extraArgs...)
	args = append(args, "-w", "\nHTTPSTATUS:%{http_code}", rawURL)

	// Give curl a grace period beyond its own --max-time before
	// killing the process at the Go level (defensive).
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(timeoutSec+10)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "curl", args...)
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	stdout, cmdErr := cmd.Output()
	if cmdErr != nil {
		return nil, cmdErr
	}
	return stdout, nil
}

// curlAttempt issues a single curl request with the given per-attempt
// timeout and returns the HTTP status code and response body.
//
// NOTE: signature and behavior unchanged — internally now delegates to the
// shared runCurl() helper so checkLocationHeader can reuse the same
// flag-building / process-exec logic without duplicating it.
func curlAttempt(rawURL string, timeoutSec int) (status int, body []byte, err error) {
	stdout, cmdErr := runCurl(rawURL, timeoutSec, true)
	if cmdErr != nil {
		return 0, nil, cmdErr
	}

	marker := []byte("\nHTTPSTATUS:")
	idx := bytes.LastIndex(stdout, marker)
	if idx < 0 {
		return 0, nil, fmt.Errorf("no HTTPSTATUS marker in output")
	}

	respBody := stdout[:idx]
	statusStr := strings.TrimSpace(string(stdout[idx+len(marker):]))
	statusCode, convErr := strconv.Atoi(statusStr)
	if convErr != nil {
		return 0, respBody, fmt.Errorf("unparseable HTTP status %q", statusStr)
	}

	return statusCode, respBody, nil
}

// curlAttemptNoRedirect issues a single curl request WITHOUT following
// redirects and with response headers captured (-D -), so the immediate
// 3xx response's Location header can be inspected. Returns the status
// code and the raw header block (everything up to, and including, the
// blank line that terminates the HTTP headers).
func curlAttemptNoRedirect(rawURL string, timeoutSec int) (status int, headerBlock string, err error) {
	stdout, cmdErr := runCurl(rawURL, timeoutSec, false, "-D", "-")
	if cmdErr != nil {
		return 0, "", cmdErr
	}

	marker := []byte("\nHTTPSTATUS:")
	idx := bytes.LastIndex(stdout, marker)
	if idx < 0 {
		return 0, "", fmt.Errorf("no HTTPSTATUS marker in output")
	}

	raw := stdout[:idx]
	statusStr := strings.TrimSpace(string(stdout[idx+len(marker):]))
	statusCode, convErr := strconv.Atoi(statusStr)
	if convErr != nil {
		return 0, string(raw), fmt.Errorf("unparseable HTTP status %q", statusStr)
	}

	// With -D -, headers are written to stdout ahead of the body (no
	// redirects are followed, so there is exactly one header block).
	// Split on the blank line ending the header section.
	headerEnd := bytes.Index(raw, []byte("\r\n\r\n"))
	sep := 4
	if headerEnd == -1 {
		headerEnd = bytes.Index(raw, []byte("\n\n"))
		sep = 2
	}
	if headerEnd == -1 {
		// No body / no blank line found (e.g. HEAD-like or truncated
		// response) — treat the entire output as the header block.
		return statusCode, string(raw), nil
	}
	return statusCode, string(raw[:headerEnd+sep]), nil
}

// extractLocationHeader scans a raw HTTP header block and returns the value
// of the (last) "Location:" header found, case-insensitively.
func extractLocationHeader(headerBlock string) (string, bool) {
	lines := strings.Split(headerBlock, "\n")
	value := ""
	found := false
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if sepIdx := strings.Index(line, ":"); sepIdx > 0 {
			key := strings.ToLower(strings.TrimSpace(line[:sepIdx]))
			if key == "location" {
				value = strings.TrimSpace(line[sepIdx+1:])
				found = true
			}
		}
	}
	return value, found
}

// hasCRLFInjection reports whether s contains a literal or percent-encoded
// (case-insensitive) CR or LF sequence, which would indicate header/response
// splitting via an injected Location value.
func hasCRLFInjection(s string) bool {
	if strings.ContainsAny(s, "\r\n") {
		return true
	}
	lower := strings.ToLower(s)
	return strings.Contains(lower, "%0d") || strings.Contains(lower, "%0a")
}

// bareCanaryOrPayload extracts the bare x9 canary from payload when
// possible, falling back to the full payload string. Used so the CRLF
// fallback check in checkLocationHeader only fires when our own injected
// marker is actually present in the header value (not on every 3xx).
func bareCanaryOrPayload(payload string) string {
	bare := reflectctx.ExtractCanary(payload)
	if bare != "" {
		return bare
	}
	return payload
}

// checkLocationHeader probes rawURL for open-redirect and Location-header
// injection issues. It never follows redirects itself so it can inspect the
// immediate 3xx response's Location header before curl's own redirect
// following would otherwise consume it. This is a separate detection mode
// from checkURL's body-reflection check and does not alter checkURL at all.
func checkLocationHeader(rawURL string, opts checkOpts) {
	payload := getDecodedPayload(rawURL)
	if payload == "" {
		return
	}

	status, headerBlock, err := curlAttemptNoRedirect(rawURL, opts.timeout)
	if err != nil || status == 0 {
		retryTimeout := opts.timeout * 2
		status, headerBlock, err = curlAttemptNoRedirect(rawURL, retryTimeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] curl failed for %s after retry (timeout=%ds then %ds): %v\n",
				rawURL, opts.timeout, retryTimeout, err)
			return
		}
	}
	if status == 0 {
		fmt.Fprintf(os.Stderr, "[ERROR] curl failed for %s: no HTTP response (status 000) even after retry\n", rawURL)
		return
	}

	if status < 300 || status > 399 {
		return
	}

	location, ok := extractLocationHeader(headerBlock)
	if !ok || location == "" {
		return
	}

	var sinkStr string
	matched := false

	// (a) Plain reflection / open-redirect: the Location value contains
	// the injected payload, and — once trimmed / URL-decoded / stripped
	// of a bare scheme prefix — is wholly dominated by it, indicating the
	// app redirects wholesale to attacker-controlled input rather than
	// merely echoing the value somewhere incidental.
	trimmedLoc := strings.TrimSpace(location)
	if strings.Contains(trimmedLoc, payload) {
		decodedLoc, decErr := url.QueryUnescape(trimmedLoc)
		if decErr != nil {
			decodedLoc = trimmedLoc
		}
		strippedLoc := strings.TrimPrefix(strings.TrimPrefix(decodedLoc, "https://"), "http://")

		if decodedLoc == payload || trimmedLoc == payload || strippedLoc == payload {
			sinkStr = "location_open_redirect"
			matched = true
		}
	}

	// (b) Breakout / header-injection reflection — only in xss mode.
	if !matched && opts.xssMode {
		marker, hasMarker := extractMarkerChar(payload)
		if hasMarker {
			bareCanary := reflectctx.ExtractCanary(payload)
			// ClassifyContext assumes an HTML/JS document context and
			// will typically return ContextUnknown for a raw header
			// value; VerifyBreakout will then simply report no match,
			// which is the correct, safe outcome for this call.
			isConfirmed, ctxType := reflectctx.VerifyBreakout([]byte(location), bareCanary, marker)
			if isConfirmed && ctxType != reflectctx.ContextUnknown {
				sinkStr = "location_header_injection"
				matched = true
			}
		}

		// Fallback: when structural context classification can't
		// confirm a breakout (expected for raw headers), directly check
		// for CRLF / header-splitting sequences in the Location value,
		// but only when our own canary is actually present so we don't
		// flag unrelated 3xx responses.
		if !matched && strings.Contains(location, bareCanaryOrPayload(payload)) && hasCRLFInjection(location) {
			sinkStr = "location_header_injection"
			matched = true
		}
	}

	if matched {
		result := DomSinkOutput{
			URL:        rawURL,
			Sinks:      []string{sinkStr},
			StatusCode: status,
		}
		opts.outMu.Lock()
		_ = json.NewEncoder(os.Stdout).Encode(result)
		opts.outMu.Unlock()
	}
}

func checkURL(rawURL string, opts checkOpts) {
	payload := getDecodedPayload(rawURL)
	if payload == "" {
		return
	}

	status, body, err := curlAttempt(rawURL, opts.timeout)
	if err != nil || status == 0 {
		retryTimeout := opts.timeout * 2
		status, body, err = curlAttempt(rawURL, retryTimeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] curl failed for %s after retry (timeout=%ds then %ds): %v\n",
				rawURL, opts.timeout, retryTimeout, err)
			return
		}
	}
	if status == 0 {
		fmt.Fprintf(os.Stderr, "[ERROR] curl failed for %s: no HTTP response (status 000) even after retry\n", rawURL)
		return
	}

	var matched bool
	var sinkStr = "body_reflection"

	if opts.xssMode {
		marker, ok := extractMarkerChar(payload)
		if !ok {
			fmt.Fprintf(os.Stderr, "[WARN] Could not determine marker char for payload %q in %s, falling back to regex\n", payload, rawURL)
			matched = xssRe.Match(body)
		} else {
			// ✅ استخراج کانری خام (بدون مارکر)
			bareCanary := reflectctx.ExtractCanary(payload)
			isConfirmed, ctxType := reflectctx.VerifyBreakout(body, bareCanary, marker)
			matched = isConfirmed
			if matched && ctxType != reflectctx.ContextUnknown {
				sinkStr = "body_reflection:" + string(ctxType)
			}
		}
	} else {
		matched = canaryRe.Match(body) && bytes.Contains(body, []byte(payload))
	}

	if matched {
		result := DomSinkOutput{
			URL:        rawURL,
			Sinks:      []string{sinkStr},
			StatusCode: status,
		}
		opts.outMu.Lock()
		_ = json.NewEncoder(os.Stdout).Encode(result)
		opts.outMu.Unlock()
	} else if status >= 400 {
		fmt.Fprintf(os.Stderr, "[INFO] %s: HTTP %d, no reflection found in body (len=%d)\n", rawURL, status, len(body))
	}
}
