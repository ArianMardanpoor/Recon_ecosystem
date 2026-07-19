package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync" // FIX BUG3: Added sync for WaitGroup and Mutex
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

const canaryHook = `
    window.__capturedSinks = [];
    const pat = /x9canary[a-z]{3}/;
    function track(sink, val) {
        if (pat.test(String(val))) window.__capturedSinks.push(sink);
    }
    const origEval = window.eval;
    window.eval = function(c) { track('eval', c); try { return origEval(c); } catch(e) {} };
    const origST = window.setTimeout;
    window.setTimeout = function(f,d) { track('setTimeout',String(f)); try { return origST(f,d); } catch(e) {} };
    const origSI = window.setInterval;
    window.setInterval = function(f,d) { track('setInterval',String(f)); try { return origSI(f,d); } catch(e) {} };
    const origDW = document.write.bind(document);
    document.write = function(c) { track('document.write',c); return origDW(c); };
    const origDWL = document.writeln.bind(document);
    document.writeln = function(c) { track('document.writeln',c); return origDWL(c); };
    var props = [
        [Element.prototype, 'innerHTML'],
        [Element.prototype, 'outerHTML'],
        [HTMLImageElement.prototype, 'src'],
        [HTMLScriptElement.prototype, 'src'],
        [HTMLIFrameElement.prototype, 'src'],
        [HTMLAnchorElement.prototype, 'href']
    ];
    props.forEach(function(item) {
        try {
            var proto = item[0], prop = item[1];
            var desc = Object.getOwnPropertyDescriptor(proto, prop);
            if (!desc || !desc.set || !desc.get) return;
            Object.defineProperty(proto, prop, {
                configurable: true,
                get: function() { return desc.get.call(this); },
                set: function(v) { 
                    var s = String(v);
                    if (s === "null" || s === "undefined" || s === "" || s === "null") return desc.set.call(this, v);
                    track(prop, v); 
                    desc.set.call(this, v); 
                }
            });
        } catch(e) {}
    });
`

const xssHook = `
    window.__capturedSinks = [];
    const pat = /x9[a-z]{3}['"` + "`" + `\\;<{]/;
    function track(sink, val) {
        if (pat.test(String(val))) window.__capturedSinks.push(sink);
    }
    const origEval = window.eval;
    window.eval = function(c) { track('eval', c); try { return origEval(c); } catch(e) {} };
    const origST = window.setTimeout;
    window.setTimeout = function(f,d) { track('setTimeout',String(f)); try { return origST(f,d); } catch(e) {} };
    const origSI = window.setInterval;
    window.setInterval = function(f,d) { track('setInterval',String(f)); try { return origSI(f,d); } catch(e) {} };
    const origDW = document.write.bind(document);
    document.write = function(c) { track('document.write',c); return origDW(c); };
    const origDWL = document.writeln.bind(document);
    document.writeln = function(c) { track('document.writeln',c); return origDWL(c); };
    var props = [
        [Element.prototype, 'innerHTML'],
        [Element.prototype, 'outerHTML'],
        [HTMLImageElement.prototype, 'src'],
        [HTMLScriptElement.prototype, 'src'],
        [HTMLIFrameElement.prototype, 'src'],
        [HTMLAnchorElement.prototype, 'href']
    ];
    props.forEach(function(item) {
        try {
            var proto = item[0], prop = item[1];
            var desc = Object.getOwnPropertyDescriptor(proto, prop);
            if (!desc || !desc.set || !desc.get) return;
            Object.defineProperty(proto, prop, {
                configurable: true,
                get: function() { return desc.get.call(this); },
                set: function(v) { 
                    var s = String(v);
                    if (s === "null" || s === "undefined" || s === "" || s === "null") return desc.set.call(this, v);
                    track(prop, v); 
                    desc.set.call(this, v); 
                }
            });
        } catch(e) {}
    });
`

type DomSinkOutput struct {
	URL   string   `json:"url"`
	Sinks []string `json:"sinks"`
}

func safeClose(page *rod.Page) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "[WARN] page close recovered: %v\n", r)
		}
	}()
	page.MustClose()
}

// FIX BUG3: Added outMu *sync.Mutex to protect standard output in parallel executions
func checkURL(browser *rod.Browser, targetURL, hookCode string, timeout int, outMu *sync.Mutex) {
	page, err := browser.Page(proto.TargetCreateTarget{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] could not create page: %v\n", err)
		return
	}
	defer safeClose(page)

	if _, err := page.EvalOnNewDocument(hookCode); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] EvalOnNewDocument failed: %v\n", err)
		return
	}

	err = page.Timeout(time.Duration(timeout) * time.Second).Navigate(targetURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] navigate failed for %s: %v\n", targetURL, err)
		return
	}

	page.Timeout(time.Duration(timeout) * time.Second).WaitLoad()
	time.Sleep(200 * time.Millisecond)

	result, err := page.Eval(`() => [...new Set(window.__capturedSinks || [])].join(",")`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] eval failed: %v\n", err)
		return
	}

	sinksStr := result.Value.String()
	if sinksStr != "" {
		var sinks []string
		for _, sink := range strings.Split(sinksStr, ",") {
			sink = strings.TrimSpace(sink)
			if sink != "" {
				sinks = append(sinks, sink)
			}
		}
		if len(sinks) > 0 {
			output := DomSinkOutput{
				URL:   targetURL,
				Sinks: sinks,
			}
			jsonData, err := json.Marshal(output)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] marshal failed: %v\n", err)
				return
			}
			// FIX BUG3: Use outMu lock to prevent output interleaving from multiple goroutines
			outMu.Lock()
			fmt.Println(string(jsonData))
			outMu.Unlock()
		}
	}
}

func main() {
	xssMode := flag.Bool("xss", false, "Use break-char pattern instead of canary pattern")
	timeout := flag.Int("timeout", 15, "Timeout per page in seconds")
	inputFile := flag.String("l", "", "Input file with URLs")
	// FIX BUG3: Added new flag for concurrency control
	concurrency := flag.Int("c", 4, "number of concurrent browser pages to check in parallel")
	flag.Parse()

	hookCode := canaryHook
	if *xssMode {
		hookCode = xssHook
	}

	u := launcher.New().NoSandbox(true).MustLaunch()
	browser := rod.New().ControlURL(u).MustConnect()
	defer browser.MustClose()

	var scanner *bufio.Scanner
	if *inputFile == "" || *inputFile == "-" {
		scanner = bufio.NewScanner(os.Stdin)
	} else {
		f, err := os.Open(*inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] cannot open file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		scanner = bufio.NewScanner(f)
	}

	// FIX BUG3: Created Mutex for thread-safe printing
	var outMu sync.Mutex

	// FIX BUG3: Implemented worker pool based on curl_reflect_checker.go pattern
	c := *concurrency
	if c < 1 {
		c = 1
	}

	urls := make(chan string, c*2)
	var wg sync.WaitGroup

	for i := 0; i < c; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range urls {
				safeCheckURL(browser, u, hookCode, *timeout, &outMu)
			}
		}()
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && strings.HasPrefix(line, "http") {
			// FIX BUG3: Push URL to channel instead of executing sequentially
			urls <- line
		}
	}

	// FIX BUG3: Close channel and wait for all workers to finish
	close(urls)
	wg.Wait()

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] reading input: %v\n", err)
		os.Exit(1)
	}
}

// FIX BUG3: Added outMu *sync.Mutex to parameter list
func safeCheckURL(browser *rod.Browser, targetURL, hookCode string, timeout int, outMu *sync.Mutex) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "[WARN] checkURL panic for %s: %v\n", targetURL, r)
		}
	}()
	checkURL(browser, targetURL, hookCode, timeout, outMu)
}
