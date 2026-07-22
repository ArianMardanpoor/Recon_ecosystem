package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"reconpipeline/pkg/reflectctx"
)

var reX9 = regexp.MustCompile(`(?:<b9|['"])?x9(?:canary)?[a-z]*(?:['"\;<{]|\{\{)?`)
var canaryRe = regexp.MustCompile(`x9canary[a-z]{3}`)
var xssRe = regexp.MustCompile(`x9[a-z]{3}['"` + "`" + `\;<{]`)

const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
	"AppleWebKit/537.36 (KHTML, like Gecko) " +
	"Chrome/126.0.0.0 Safari/537.36"

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
	rawMatch := reX9.FindString(rawURL)
	if rawMatch != "" {
		if unescaped, err := url.QueryUnescape(rawMatch); err == nil {
			return unescaped
		}
		return rawMatch
	}
	return ""
}

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

func main() {
	xssMode := flag.Bool("xss", false, "Enable Phase 4 xss/breakout marker verification")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: debug_reflect_probe [-xss] <URL>")
		os.Exit(1)
	}
	rawURL := flag.Arg(0)

	fmt.Println("==================================================")
	fmt.Printf("[*] TARGET URL      : %s\n", rawURL)
	fmt.Printf("[*] MODE            : %s\n", map[bool]string{true: "Phase 4 (Breakout/Context)", false: "Phase 3 (Plain Canary)"}[*xssMode])

	payload := getDecodedPayload(rawURL)
	fmt.Printf("[*] DECODED PAYLOAD : %q\n", payload)

	if payload == "" {
		fmt.Println("[!] FATAL: Could not extract payload from URL.")
		os.Exit(1)
	}

	var marker byte
	var markerOk bool
	if *xssMode {
		marker, markerOk = extractMarkerChar(payload)
		if markerOk {
			fmt.Printf("[*] EXTRACTED MARKER: %q (ASCII: %d)\n", marker, marker)
		} else {
			fmt.Println("[*] EXTRACTED MARKER: NOT DETECTED")
		}
	}

	fmt.Println("\n[*] Executing HTTP request via curlAttempt (timeout=20s)...")
	status, body, err := curlAttempt(rawURL, 20)
	if err != nil {
		fmt.Printf("[!] HTTP Request failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[*] HTTP Status     : %d\n", status)
	fmt.Printf("[*] Body Length     : %d bytes\n", len(body))

	debugFile := "/tmp/debug_body.html"
	if err := os.WriteFile(debugFile, body, 0644); err == nil {
		fmt.Printf("[*] Body saved to   : %s\n", debugFile)
	} else {
		fmt.Printf("[!] Failed to save body to %s: %v\n", debugFile, err)
	}

	fmt.Println("\n--- BODY INSPECTION ---")
	canaryBytes := []byte(payload)

	if !bytes.Contains(body, canaryBytes) {
		fmt.Println("[!] NOT FOUND IN BODY AT ALL")
	} else {
		offset := 0
		occurrence := 1
		for {
			idx := bytes.Index(body[offset:], canaryBytes)
			if idx == -1 {
				break
			}
			actualIdx := offset + idx
			fmt.Printf("\n>>> Occurrence #%d at offset %d <<<\n", occurrence, actualIdx)

			start := actualIdx - 60
			if start < 0 {
				start = 0
			}
			end := actualIdx + len(canaryBytes) + 60
			if end > len(body) {
				end = len(body)
			}

			fmt.Printf("    Context (-60/+60): %q\n", body[start:end])

			ctx := reflectctx.ClassifyContext(body, actualIdx)
			fmt.Printf("    ClassifyContext  : %+v\n", ctx)

			offset = actualIdx + len(canaryBytes)
			occurrence++
		}
	}

	fmt.Println("\n--- FINAL VERDICT ---")
	if *xssMode {
		if !markerOk {
			fmt.Println("VERDICT: NOT CONFIRMED (Breakout)")
			fmt.Println("REASON : No marker detected in payload, falling back to regex.")
			matched := xssRe.Match(body)
			fmt.Printf("REGEX FALLBACK MATCH: %v\n", matched)
		} else {
			// ✅ استخراج کانری خام (بدون مارکر)
			bareCanary := reflectctx.ExtractCanary(payload)
			isConfirmed, ctxType := reflectctx.VerifyBreakout(body, bareCanary, marker)
			fmt.Printf("VerifyBreakout() -> %v, %s\n", isConfirmed, ctxType)
			if isConfirmed {
				fmt.Printf("VERDICT: CONFIRMED (Breakout in %s context)\n", ctxType)
			} else {
				fmt.Println("VERDICT: NOT CONFIRMED (Breakout)")
				fmt.Println("REASON : VerifyBreakout returned false (likely safely escaped or truncated).")
			}
		}
	} else {
		matched := canaryRe.Match(body) && bytes.Contains(body, canaryBytes)
		if matched {
			fmt.Println("VERDICT: CONFIRMED (Phase 3 Plain Canary)")
		} else {
			fmt.Println("VERDICT: NOT CONFIRMED (Phase 3 Plain Canary)")
			if bytes.Contains(body, canaryBytes) && !canaryRe.Match(body) {
				fmt.Println("REASON : bytes.Contains matched, but canaryRe regex failed. Was the payload mangled?")
			} else {
				fmt.Println("REASON : bytes.Contains failed. The payload is not in the body.")
			}
		}
	}
	fmt.Println("==================================================")
}
