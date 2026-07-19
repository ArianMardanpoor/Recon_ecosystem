// curl_reflect_checker.go — standalone canary/break-char reflection detector
// that issues HTTP requests via the curl binary (exec'd) instead of Go's
// net/http, avoiding JA3/TLS fingerprinting by WAFs (F5, Volterra, …).
//
// Behaviour mirrors nuclei's canary_matcher.yaml / xss_template_v2.yaml
// matchers but uses curl (OpenSSL/libcurl TLS stack) so that WAFs that
// block Go's net/http JA3 no longer cause false negatives.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// reX9 extracts the canary / break-char payload embedded in the URL.
// Mirrors xssniper.go's reX9:  x9(?:canary)?[a-z]*
var reX9 = regexp.MustCompile(`x9(?:canary)?[a-z]*`)

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
// FIX BUG4: Added StatusCode field for visibility into HTTP response codes.
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

func main() {
	listFile := flag.String("l", "", "input file with one URL per line (use - for stdin)")
	xssMode := flag.Bool("xss", false, "search for break-char pattern instead of plain canary")
	timeout := flag.Int("timeout", 15, "per-request curl timeout in seconds")
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

func checkURL(rawURL string, opts checkOpts) {
	// Extract the payload substring from the URL so we know what to
	// search for in the response body (same approach as xssniper.go).
	payload := reX9.FindString(rawURL)
	if payload == "" {
		return
	}

	args := []string{
		"-s",
		"-L",
		"--max-time", strconv.Itoa(opts.timeout),
		"-A", userAgent,
		"-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
		"-H", "Accept-Language: en-US,en;q=0.9",
		"-w", "\\nHTTPSTATUS:%{http_code}",
		rawURL,
	}

	// Give curl a grace period beyond its own --max-time before
	// killing the process at the Go level (defensive).
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(opts.timeout+10)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "curl", args...)
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	stdout, err := cmd.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] curl failed for %s: %v\n", rawURL, err)
		return
	}

	// Split off the trailing  \nHTTPSTATUS:<code>  marker that curl's
	// -w appends to stdout.
	marker := []byte("\nHTTPSTATUS:")
	idx := bytes.LastIndex(stdout, marker)
	if idx < 0 {
		fmt.Fprintf(os.Stderr, "[ERROR] curl failed for %s: no HTTPSTATUS marker in output\n", rawURL)
		return
	}

	body := stdout[:idx]
	statusStr := strings.TrimSpace(string(stdout[idx+len(marker):]))
	status, err := strconv.Atoi(statusStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] curl failed for %s: unparseable HTTP status %q\n", rawURL, statusStr)
		return
	}

	if status == 0 {
		fmt.Fprintf(os.Stderr, "[ERROR] curl failed for %s: no HTTP response (status 000)\n", rawURL)
		return
	}

	// FIX BUG4: Removed the `if status >= 400 { return }` block entirely
	// to ensure we check response bodies of 4xx/5xx error pages for reflection.

	// Check for reflection in the response body.
	var matched bool
	if opts.xssMode {
		matched = xssRe.Match(body)
	} else {
		matched = canaryRe.Match(body) && bytes.Contains(body, []byte(payload))
	}

	if matched {
		result := DomSinkOutput{
			URL:        rawURL,
			Sinks:      []string{"body_reflection"},
			StatusCode: status, // FIX BUG4: Added actual HTTP status code for debugging/visibility
		}
		opts.outMu.Lock()
		_ = json.NewEncoder(os.Stdout).Encode(result)
		opts.outMu.Unlock()
	} else if status >= 400 {
		// FIX BUG4: Informational log for high status codes without valid reflection.
		fmt.Fprintf(os.Stderr, "[INFO] %s: HTTP %d, no reflection found in body (len=%d)\n", rawURL, status, len(body))
	}
}
