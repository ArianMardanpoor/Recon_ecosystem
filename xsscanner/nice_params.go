package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"reconpipeline/pkg/reporter"
)

var repLogger *reporter.Logger

// ─── ANSI Colors ───────────────────────────────────────────────────────────────

const (
	PR_boldGreen  = "\033[1;32m"
	PR_boldYellow = "\033[1;33m"
	PR_boldRed    = "\033[1;31m"
	PR_boldBlue   = "\033[1;34m"
	PR_boldCyan   = "\033[1;36m"
	PR_boldWhite  = "\033[1;37m"
	PR_dimWhite   = "\033[2;37m"
	PR_reset      = "\033[0m"
)

// ─── Regexes ───────────────────────────────────────────────────────────────────

var (
	x8ParamRegex = regexp.MustCompile(`(?:GET|POST)\s+\S+\s+%\s+(.+)`)
	cleanupRegex = regexp.MustCompile(`%+$`)
	x8FoundRegex = regexp.MustCompile(`\[\+\]\s+(\w[\w\-.]*)`)

	reNumeric = regexp.MustCompile(`^\d+$`)
	reCSSUnit = regexp.MustCompile(`\d+(px|em|rem|vh|vw|ms|fr)$`)
)

// ─── Config & State ────────────────────────────────────────────────────────────

type Config struct {
	URL       string
	URLFile   string
	OutDir    string // Directory to save HOST-param.txt files
	Wordlist  string
	Silent    bool
	KeepTemp  bool
	Threads   int
	Timeout   int
	NoX8      bool
	NoFall    bool
	MaxParams int
}

var (
	tempFiles []string
	tempMu    sync.Mutex
	printMu   sync.Mutex
	logMu     sync.Mutex // New mutex for logging in silent mode
)

// ─── Cleanup ───────────────────────────────────────────────────────────────────

func registerTemp(path string) {
	tempMu.Lock()
	tempFiles = append(tempFiles, path)
	tempMu.Unlock()
}

func cleanup() {
	tempMu.Lock()
	defer tempMu.Unlock()
	for _, f := range tempFiles {
		os.RemoveAll(f)
	}
}

// ─── Printing & Logging ────────────────────────────────────────────────────────

func printf(format string, args ...interface{}) {
	printMu.Lock()
	fmt.Printf(format, args...)
	printMu.Unlock()
}

func logErrorMsg(msg string) {
	logMu.Lock()
	defer logMu.Unlock()
	fmt.Fprintf(os.Stderr, "[ERROR] %s\n", msg)
}

func printInfo(msg string)    { printf("%s[*]%s %s\n", PR_boldBlue, PR_reset, msg) }
func printSuccess(msg string) { printf("%s[+]%s %s\n", PR_boldGreen, PR_reset, msg) }
func printWarning(msg string) { printf("%s[!]%s %s\n", PR_boldYellow, PR_reset, msg) }
func printError(msg string)   { printf("%s[-]%s %s\n", PR_boldRed, PR_reset, msg) }
func printStep(msg string)    { printf("%s[>]%s %s\n", PR_boldBlue, PR_reset, msg) }

func printSep() {
	printf("%s%s%s\n", PR_dimWhite, strings.Repeat("─", 50), PR_reset)
}

// ─── Output File Naming ────────────────────────────────────────────────────────

func getHostFilename(rawURL, outDir string) string {
	parsed, err := url.Parse(rawURL)
	var host string
	if err == nil && parsed.Hostname() != "" {
		host = parsed.Hostname()
	} else {
		// Fallback for weird URLs
		host = strings.ReplaceAll(rawURL, "https://", "")
		host = strings.ReplaceAll(host, "http://", "")
		host = strings.Split(host, "/")[0]
	}

	// Example: asda.com-param.txt
	filename := host + "-param.txt"
	return filepath.Join(outDir, filename)
}

// ─── Param Helpers ─────────────────────────────────────────────────────────────

func cleanParam(p string) string {
	p = cleanupRegex.ReplaceAllString(p, "")
	p = strings.ReplaceAll(p, "payload%", "payload")
	p = strings.TrimSpace(p)
	return p
}

func isValidParam(p string) bool {
	// Length window 2-50
	if len(p) < 2 || len(p) > 50 {
		return false
	}
	// Reject pure numeric
	if reNumeric.MatchString(p) {
		return false
	}
	// Reject CSS variables
	if strings.HasPrefix(p, "--") {
		return false
	}
	// Reject whitespace
	if strings.ContainsAny(p, " \t\n\r") {
		return false
	}
	// Reject CSS units
	if reCSSUnit.MatchString(p) {
		return false
	}
	return true
}

func readParams(filename string) ([]string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var out []string
	sc := bufio.NewScanner(strings.NewReader(string(content)))
	for sc.Scan() {
		p := cleanParam(sc.Text())
		if p != "" && !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "\\") && isValidParam(p) && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, nil
}

var fileMu sync.Mutex

func writeHostParamFile(outFile string, x8Params []string, fallParams []string, maxParams int) (int, error) {
	fileMu.Lock()
	defer fileMu.Unlock()

	existing, err := readParams(outFile)
	if err != nil && !os.IsNotExist(err) {
		logErrorMsg(fmt.Sprintf("failed to read existing params from %s: %v", outFile, err))
	}

	seen := make(map[string]bool)
	var final []string

	// 1. Prioritize existing content
	for _, p := range existing {
		if !seen[p] && len(final) < maxParams {
			seen[p] = true
			final = append(final, p)
		}
	}

	// 2. Prioritize X8 parameters
	x8Dropped := 0
	for _, p := range x8Params {
		p = cleanParam(p)
		if p != "" && !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "\\") && isValidParam(p) && !seen[p] {
			if len(final) < maxParams {
				seen[p] = true
				final = append(final, p)
			} else {
				x8Dropped++
			}
		}
	}

	// 3. Finally Fallparams
	fallDropped := 0
	for _, p := range fallParams {
		p = cleanParam(p)
		if p != "" && !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "\\") && isValidParam(p) && !seen[p] {
			if len(final) < maxParams {
				seen[p] = true
				final = append(final, p)
			} else {
				fallDropped++
			}
		}
	}

	if x8Dropped > 0 || fallDropped > 0 {
		msg := fmt.Sprintf("Max params (%d) reached for %s. Dropped %d x8 and %d fallparams.", maxParams, filepath.Base(outFile), x8Dropped, fallDropped)
		printWarning(msg)
	}

	if len(final) == len(existing) {
		return 0, nil
	}

	host := strings.TrimSuffix(filepath.Base(outFile), "-param.txt")
	for _, p := range final[len(existing):] {
		repLogger.Log(reporter.NewFinding(
			host, outFile, p, "fallparams/x8", "MEDIUM", "parameter_discovered",
			reporter.Context{Location: "discovered parameter list"},
		))
	}

	f, err := os.Create(outFile)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	for _, p := range final {
		fmt.Fprintln(f, p)
	}
	return len(final) - len(existing), nil
}

// ─── Tool Check ────────────────────────────────────────────────────────────────

func checkTool(toolName string) error {
	_, err := exec.LookPath(toolName)
	if err != nil {
		return fmt.Errorf("%s not found in PATH. Please install it to use this feature.", toolName)
	}
	return nil
}

// ─── fallparams — Contextual Wordlist Generator ────────────────────────────────

func isCandidateWord(w string) bool {
	if w == "" || len(w) > 100 {
		return false
	}
	if strings.ContainsAny(w, " \t\n\r") {
		return false
	}
	if strings.HasPrefix(w, "/") || strings.HasPrefix(w, "\\") {
		return false
	}
	return true
}

func runFallparams(ctx context.Context, rawURL string, silent bool) ([]string, error) {
	if err := checkTool("fallparams"); err != nil {
		return nil, err
	}

	if !silent {
		printStep(fmt.Sprintf("fallparams → %s (contextual wordlist gen)", rawURL))
	}

	runDir, err := os.MkdirTemp("", "fall_isolate_*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory for fallparams: %v", err)
	}
	registerTemp(runDir)

	cmd := exec.CommandContext(ctx, "fallparams", "-u", rawURL)
	cmd.Dir = runDir

	_, _ = cmd.CombinedOutput()

	fallOutPath := filepath.Join(runDir, "parameters.txt")
	content, err := os.ReadFile(fallOutPath)
	if err != nil {
		if !silent {
			printInfo("fallparams: no output file found")
		}
		return nil, nil
	}

	var candidates []string
	seen := make(map[string]bool)
	sc := bufio.NewScanner(strings.NewReader(string(content)))
	for sc.Scan() {
		w := strings.TrimSpace(sc.Text())
		w = cleanParam(w)
		if isCandidateWord(w) && !seen[w] {
			seen[w] = true
			candidates = append(candidates, w)
		}
	}

	if !silent {
		if len(candidates) > 0 {
			printSuccess(fmt.Sprintf("fallparams: %d candidate words extracted (feeding to x8 wordlist)", len(candidates)))
		} else {
			printInfo("fallparams: no candidate words found")
		}
	}
	return candidates, nil
}

// ─── Wordlist Merging ──────────────────────────────────────────────────────────

func buildCombinedWordlist(baseWordlist string, candidates []string) (string, int, error) {
	base, err := os.ReadFile(baseWordlist)
	if err != nil {
		return "", 0, fmt.Errorf("failed to read base wordlist %s: %v", baseWordlist, err)
	}

	seen := make(map[string]bool)
	var lines []string

	sc := bufio.NewScanner(strings.NewReader(string(base)))
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)
	for sc.Scan() {
		w := strings.TrimSpace(sc.Text())
		if w == "" || seen[w] {
			continue
		}
		seen[w] = true
		lines = append(lines, w)
	}

	added := 0
	for _, w := range candidates {
		if seen[w] {
			continue
		}
		seen[w] = true
		lines = append(lines, w)
		added++
	}

	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("combined_wordlist_%d_%d.txt", os.Getpid(), time.Now().UnixNano()))
	f, err := os.Create(tmpFile)
	if err != nil {
		return "", 0, fmt.Errorf("failed to create combined wordlist %s: %v", tmpFile, err)
	}
	for _, w := range lines {
		fmt.Fprintln(f, w)
	}
	f.Close()

	return tmpFile, added, nil
}

// ─── x8 ───────────────────────────────────────────────────────────────────────

func extractX8Params(content string) []string {
	seen := make(map[string]bool)
	var out []string

	addParam := func(p string) {
		p = cleanParam(p)
		if p != "" && !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "\\") && isValidParam(p) && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}

	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		if m := x8ParamRegex.FindStringSubmatch(line); len(m) > 1 {
			for _, part := range strings.Split(m[1], ",") {
				addParam(strings.TrimSpace(part))
			}
			continue
		}
		if m := x8FoundRegex.FindStringSubmatch(line); len(m) > 1 {
			addParam(m[1])
			continue
		}

		if !strings.ContainsAny(line, " [:]") {
			addParam(line)
		}
	}
	return out
}

func runX8(ctx context.Context, rawURL, wordlist string, silent bool) ([]string, error) {
	if err := checkTool("x8"); err != nil {
		return nil, err
	}

	if !silent {
		printStep(fmt.Sprintf("x8 → %s", rawURL))
	}

	if _, err := os.Stat(wordlist); os.IsNotExist(err) {
		return nil, fmt.Errorf("wordlist not found: %s", wordlist)
	}

	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("x8_%d_%d.txt", os.Getpid(), time.Now().UnixNano()))
	registerTemp(tmpFile)

	args := []string{
		"-u", rawURL,
		"-w", wordlist,
		"-o", tmpFile,
		"-c", "5",
		"--delay", "1",
		"--timeout", "15",
		"-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	}
	cmd := exec.CommandContext(ctx, "x8", args...)

	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := fmt.Sprintf("x8 exited non-zero (%v). Output: %s", err, string(out))
		if !silent {
			printWarning(msg)
		} else {
			logErrorMsg(msg)
		}
	}

	content, readErr := os.ReadFile(tmpFile)
	if readErr != nil {
		return nil, fmt.Errorf("failed to read x8 output file %s: %v", tmpFile, readErr)
	}

	params := extractX8Params(string(content))

	if !silent {
		if len(params) > 0 {
			printSuccess(fmt.Sprintf("x8: %d params found", len(params)))
		} else {
			printInfo("x8: no params found")
		}
	}
	return params, nil
}

// ─── URL Processor ─────────────────────────────────────────────────────────────

type Result struct {
	URL        string
	OutFile    string
	X8Params   []string
	FallParams []string
	Err        error
}

func processURL(ctx context.Context, rawURL string, cfg *Config) Result {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return Result{URL: rawURL, Err: fmt.Errorf("invalid URL (must start with http:// or https://)")}
	}

	outFile := getHostFilename(rawURL, cfg.OutDir)
	toolCtx, cancel := context.WithTimeout(ctx, time.Duration(cfg.Timeout)*time.Second)
	defer cancel()

	var res Result
	res.URL = rawURL
	res.OutFile = outFile

	var fallErr, x8Err error
	var candidates []string

	if !cfg.NoFall {
		words, err := runFallparams(toolCtx, rawURL, cfg.Silent)
		if err != nil {
			fallErr = fmt.Errorf("fallparams error for %s: %v", rawURL, err)
			if !cfg.Silent {
				printError(fallErr.Error())
			} else {
				logErrorMsg(fallErr.Error())
			}
		} else {
			candidates = words
		}
	}

	if !cfg.NoX8 {
		x8Wordlist := cfg.Wordlist

		if len(candidates) > 0 {
			combinedPath, added, buildErr := buildCombinedWordlist(cfg.Wordlist, candidates)
			if buildErr != nil {
				msg := fmt.Sprintf("failed to build combined wordlist for %s (falling back to base wordlist): %v", rawURL, buildErr)
				if !cfg.Silent {
					printWarning(msg)
				} else {
					logErrorMsg(msg)
				}
			} else {
				x8Wordlist = combinedPath
				registerTemp(combinedPath)
				defer func() {
					if !cfg.KeepTemp {
						os.Remove(combinedPath)
					}
				}()
				if !cfg.Silent {
					printInfo(fmt.Sprintf("merged %d fallparams candidates into combined wordlist for x8", added))
				}
			}
		}

		params, err := runX8(toolCtx, rawURL, x8Wordlist, cfg.Silent)
		if err != nil {
			x8Err = fmt.Errorf("x8 error for %s: %v", rawURL, err)
			if !cfg.Silent {
				printError(x8Err.Error())
			} else {
				logErrorMsg(x8Err.Error())
			}
		} else {
			res.X8Params = params
		}
	} else if len(candidates) > 0 {
		res.FallParams = candidates
	}

	if fallErr != nil && x8Err != nil {
		res.Err = fmt.Errorf("%v; %v", fallErr, x8Err)
	} else if fallErr != nil {
		res.Err = fallErr
	} else if x8Err != nil {
		res.Err = x8Err
	}

	return res
}

// ─── Multi-URL with worker pool ────────────────────────────────────────────────

func processURLFile(ctx context.Context, cfg *Config) error {
	f, err := os.Open(cfg.URLFile)
	if err != nil {
		return fmt.Errorf("cannot open URL file: %v", err)
	}
	defer f.Close()

	var urls []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		u := strings.TrimSpace(sc.Text())
		if u == "" || strings.HasPrefix(u, "#") {
			continue
		}
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			u = "https://" + u
		}
		urls = append(urls, u)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("reading URL file: %v", err)
	}
	if len(urls) == 0 {
		return fmt.Errorf("no valid URLs found in %s", cfg.URLFile)
	}

	if !cfg.Silent {
		printInfo(fmt.Sprintf("Loaded %d URLs — %d worker(s) — saving to %s/", len(urls), cfg.Threads, cfg.OutDir))
		printSep()
	}

	jobs := make(chan string, len(urls))
	results := make(chan Result, len(urls))
	var successCount int64
	var totalFound int64

	var wg sync.WaitGroup
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range jobs {
				results <- processURL(ctx, u, cfg)
			}
		}()
	}

	for _, u := range urls {
		jobs <- u
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	processed := 0
	for res := range results {
		processed++
		if !cfg.Silent {
			printSep()
			printf("%s[%d/%d]%s %s\n", PR_boldWhite, processed, len(urls), PR_reset, res.URL)
		}
		if res.Err != nil {
			if !cfg.Silent {
				printError(res.Err.Error())
			} else {
				logErrorMsg(res.Err.Error())
			}
			continue
		}

		atomic.AddInt64(&successCount, 1)

		if len(res.X8Params) > 0 || len(res.FallParams) > 0 {
			added, _ := writeHostParamFile(res.OutFile, res.X8Params, res.FallParams, cfg.MaxParams)
			atomic.AddInt64(&totalFound, int64(added))
			if !cfg.Silent {
				if added > 0 {
					printSuccess(fmt.Sprintf("%d new unique params saved to %s", added, res.OutFile))
				} else {
					printInfo(fmt.Sprintf("Params found, but already existed or cap reached in %s", res.OutFile))
				}
			}
		} else if !cfg.Silent {
			printInfo("no params found")
		}
	}

	if !cfg.Silent {
		printSep()
		printf("\n")
		printSuccess(fmt.Sprintf("Done! %d/%d URLs succeeded", successCount, len(urls)))
		printSuccess(fmt.Sprintf("Total unique parameters found: %d", totalFound))
	}
	return nil
}

// ─── Main ──────────────────────────────────────────────────────────────────────

func main() {
	cfg := &Config{}

	flag.StringVar(&cfg.URL, "u", "", "Target URL (single)")
	flag.StringVar(&cfg.URL, "url", "", "Target URL (single, alias)")
	flag.StringVar(&cfg.URLFile, "f", "", "File with list of URLs (one per line)")
	flag.StringVar(&cfg.URLFile, "file", "", "File with list of URLs (alias)")
	flag.StringVar(&cfg.OutDir, "d", "results/params", "Output directory to save <HOST>-param.txt files")
	flag.StringVar(&cfg.OutDir, "dir", "results/params", "Output directory (alias)")
	flag.StringVar(&cfg.Wordlist, "w", "", "Wordlist for x8 (default: param.txt next to nice_params)")
	flag.BoolVar(&cfg.Silent, "silent", false, "No terminal output (machine-friendly)")
	flag.BoolVar(&cfg.KeepTemp, "keep-temp", false, "Keep temporary files after exit")
	flag.IntVar(&cfg.Threads, "t", 5, "Concurrent workers (for -f mode)")
	flag.IntVar(&cfg.Timeout, "timeout", 300, "Per-tool timeout in seconds")
	flag.BoolVar(&cfg.NoX8, "no-x8", false, "Skip x8 (fallparams only)")
	flag.BoolVar(&cfg.NoFall, "no-fall", false, "Skip fallparams (x8 only)")
	flag.IntVar(&cfg.MaxParams, "max-params", 200, "Maximum number of parameters to keep per host")

	flag.Usage = func() {
		printf("%sUsage:%s\n", PR_boldYellow, PR_reset)
		printf("  nice_params -u <URL>                        Single URL\n")
		printf("  nice_params -f <file>                       Bulk URLs from file\n")
		printf("  nice_params -u <URL> -w <wordlist>          Custom wordlist for x8\n")
		printf("  nice_params -f urls.txt -d results/         Save host-param.txt files to custom dir\n")
		printf("  nice_params -f urls.txt -t 10               10 concurrent workers\n\n")
		printf("%sOutput:%s\n", PR_boldYellow, PR_reset)
		printf("  Files are automatically named <HOST>-param.txt (e.g. asda.com-param.txt)\n\n")
		printf("%sFlags:%s\n", PR_boldYellow, PR_reset)
		flag.PrintDefaults()
	}

	flag.Parse()
	var err error
	repLogger, err = reporter.NewLogger("results/raw_findings.jsonl")
	if err != nil {
		printError(fmt.Sprintf("reporter init failed: %v", err))
		os.Exit(1)
	}

	if cfg.Wordlist == "" {
		// ابتدا بررسی دایرکتوری محل قرارگیری خود فایل اجرایی (بهینه برای فایل کامپایل‌شده)
		exePath, err := os.Executable()
		if err == nil {
			target := filepath.Join(filepath.Dir(exePath), "param.txt")
			if _, err := os.Stat(target); err == nil {
				cfg.Wordlist = target
			}
		}
		// اگر در مسیر بالا پیدا نشد (مثلا موقع کار با go run)، مستقیماً در دایرکتوری فعلی ترمینال دنبالش می‌گردد
		if cfg.Wordlist == "" {
			cfg.Wordlist = "param.txt"
		}
	}

	if cfg.URL != "" && cfg.URLFile != "" {
		printError("use either -u or -f, not both")
		os.Exit(1)
	}

	if cfg.URL == "" && cfg.URLFile == "" {
		printError("specify -u <URL> or -f <file>")
		flag.Usage()
		os.Exit(1)
	}

	if cfg.Threads < 1 {
		cfg.Threads = 1
	}

	if err := os.MkdirAll(cfg.OutDir, 0755); err != nil {
		printError(fmt.Sprintf("failed to create output directory: %v", err))
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		if !cfg.Silent {
			printf("\n%s[!]%s Interrupted — cleaning up…\n", PR_boldYellow, PR_reset)
		}
		cancel()
	}()

	if !cfg.KeepTemp {
		defer cleanup()
	}

	if !cfg.NoFall {
		if err := checkTool("fallparams"); err != nil {
			printError(err.Error())
			os.Exit(1)
		}
	}
	if !cfg.NoX8 {
		if err := checkTool("x8"); err != nil {
			printError(err.Error())
			os.Exit(1)
		}
	}

	if cfg.URL != "" {
		res := processURL(ctx, cfg.URL, cfg)
		if res.Err != nil {
			printError(res.Err.Error())
			os.Exit(1)
		}

		if len(res.X8Params) > 0 || len(res.FallParams) > 0 {
			added, _ := writeHostParamFile(res.OutFile, res.X8Params, res.FallParams, cfg.MaxParams)
			if !cfg.Silent {
				printSep()
				total := len(res.X8Params) + len(res.FallParams)
				printSuccess(fmt.Sprintf("Found %d unique params (saved %d new to %s)", total, added, res.OutFile))
			}
		} else if !cfg.Silent {
			printSep()
			printInfo("No params found")
		}
		return
	}

	if cfg.URLFile != "" {
		if err := processURLFile(ctx, cfg); err != nil {
			printError(err.Error())
			os.Exit(1)
		}
	}
}
