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
				checkURL(u, opts)
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

// curlAttempt issues a single curl request with the given per-attempt
// timeout and returns the HTTP status code and response body.
func curlAttempt(rawURL string, timeoutSec int) (status int, body []byte, err error) {
	args := []string{
		"-s",
		"-L",
		"--max-time", strconv.Itoa(timeoutSec),
		"-A", userAgent,
		"-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
		"-H", "Accept-Language: en-US,en;q=0.9",
		"-w", "\nHTTPSTATUS:%{http_code}",
		rawURL,
	}

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
