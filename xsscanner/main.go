// main.go
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"reconpipeline/pkg/reporter"
	"reconpipeline/pkg/spadetect"
	"reconpipeline/utils"
)

var logWriter io.Writer = os.Stdout // Defaults to Stdout before being overridden
var repLogger *reporter.Logger

const (
	M_gray   = "\033[90m"
	M_reset  = "\033[0m"
	M_purple = "\033[35m"
	M_bold   = "\033[1m"
	M_red    = "\033[31m"
	M_green  = "\033[32m"
	M_cyan   = "\033[36m"
)

var (
	apiURL          = "http://localhost:3131/api/http"
	apiToken        = "a21uc0lzeTcK"
	oldTargetsFile  = "all_scanned_targets.txt"
	globalOutputDir = "./results"
)

func logMsg(msg string, color string) {
	ts := time.Now().Format("15:04:05")
	fmt.Fprintf(logWriter, "%s[%s]%s %s[BRIDGE] %s%s\n", M_gray, ts, M_reset, color, msg, M_reset)
}

// Minimal loadEnv helper to mimic xssniper's standard local pattern
func loadEnv() {
	f, err := os.Open(".env")
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			os.Setenv(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
}

// sendTelegramDoc sends the log document as multipart/form-data
func sendTelegramDoc(token, chatID, filePath, caption string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	_ = writer.WriteField("chat_id", chatID)
	_ = writer.WriteField("caption", caption)

	part, err := writer.CreateFormFile("document", filepath.Base(filePath))
	if err != nil {
		return err
	}
	if _, err = io.Copy(part, file); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}

	urlStr := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", token)
	req, err := http.NewRequest("POST", urlStr, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

type APIResponse struct {
	Data []struct {
		URL      string `json:"url"`
		FinalURL string `json:"final_url"`
	} `json:"data"`
	Pages int `json:"pages"`
}

func fetchDataFromAPI(mode string) []string {
	logMsg(fmt.Sprintf("Connecting to API in %s mode...", strings.ToUpper(mode)), M_cyan)
	var allURLs []string
	currentPage := 1
	perPage := 500

	for {
		urlStr := fmt.Sprintf("%s?page=%d&per_page=%d", apiURL, currentPage, perPage)
		if mode == "fresh" {
			urlStr += "&only_changed=true"
		}

		req, _ := http.NewRequest("GET", urlStr, nil)
		req.Header.Set("X-API-Token", apiToken)
		req.Header.Set("Accept", "application/json")

		client := &http.Client{Timeout: 60 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			logMsg(fmt.Sprintf("API Error: %v", err), M_red)
			break
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			logMsg(fmt.Sprintf("API returned status: %d", resp.StatusCode), M_red)
			break
		}

		var apiResp APIResponse
		if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
			logMsg(fmt.Sprintf("JSON Decode Error: %v", err), M_red)
			break
		}

		for _, item := range apiResp.Data {
			target := item.FinalURL
			if target == "" {
				target = item.URL
			}
			if target != "" {
				allURLs = append(allURLs, target)
			}
		}

		if currentPage >= apiResp.Pages || apiResp.Pages == 0 {
			break
		}
		currentPage++
	}

	logMsg(fmt.Sprintf("Total unique URLs retrieved from API: %d", len(allURLs)), M_cyan)
	return allURLs
}

func getNewTargetsOnly(targets []string) []string {
	logMsg("Checking for new targets (Diffing)...", M_cyan)
	scanned := make(map[string]bool)
	file, err := os.Open(oldTargetsFile)
	if err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			scanned[strings.TrimSpace(scanner.Text())] = true
		}
		file.Close()
	}

	var newTargets []string
	for _, t := range targets {
		if !scanned[t] {
			newTargets = append(newTargets, t)
		}
	}
	return newTargets
}

func markAsScanned(urlStr string) {
	f, err := os.OpenFile(oldTargetsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(urlStr + "\n")
	logMsg(fmt.Sprintf("Target marked as scanned: %s", urlStr), M_green)
}

func runBinary(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = logWriter // Redirect stdout to multi-writer
	cmd.Stderr = logWriter // Redirect stderr to multi-writer
	return cmd.Run()
}

func getSafeName(u string) string {
	return regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(u, "_")
}

func countLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			n++
		}
	}
	return n
}
func countLinesInDir(dir string) int {
	total := 0
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	for _, e := range entries {
		if !e.IsDir() {
			total += countLines(filepath.Join(dir, e.Name()))
		}
	}
	return total
}

// ── تابع پردازش هدف (Sequential Waterfall) ─────────────────────────────────

func processTarget(target string, isSingleTarget bool, skipSPA bool, noCrawl bool, phase int) {
	logMsg(fmt.Sprintf("--- Starting: %s ---", target), M_purple+M_bold)

	u, err := url.Parse(target)
	if err != nil {
		logMsg(fmt.Sprintf("Invalid URL: %s", target), M_red)
		return
	}
	hostname := u.Hostname()
	if hostname == "" {
		hostname = target
	}
	safeURL := getSafeName(target)
	rootDomain := utils.ExtractRootDomain(hostname)

	passiveDir := filepath.Join(globalOutputDir, "passive")
	katanaDir := filepath.Join(globalOutputDir, "katana")
	paramsDir := filepath.Join(globalOutputDir, "params")

	os.MkdirAll(passiveDir, 0755)
	os.MkdirAll(katanaDir, 0755)
	os.MkdirAll(paramsDir, 0755)

	passiveOutFile := filepath.Join(passiveDir, hostname+".passive")
	katanaOutFile := filepath.Join(katanaDir, safeURL+"-katana.txt")

	if !noCrawl {
		// STEP 1: Passive discovery (must finish before anything else starts)
		logMsg(fmt.Sprintf("[1/3] Running nice_passive for %s", target), M_gray)
		if err := runBinary("./nice_passive", "-o", passiveDir, hostname); err != nil {
			logMsg(fmt.Sprintf("nice_passive failed for %s: %v", target, err), M_red)
		}

		// STEP 2: Katana runs ONLY on the unique output of passive phase
		if countLines(passiveOutFile) > 0 {
			if spadetect.IsSPA(target) {
				logMsg(fmt.Sprintf("[SKIP-SPA] %s: SPA detected, skipping katana crawl", target), M_cyan)
			} else {
				logMsg(fmt.Sprintf("[2/3] Running nice_katana on passive results for %s", target), M_gray)
				if err := runBinary("./nice_katana", "-o", katanaDir, passiveOutFile); err != nil {
					logMsg(fmt.Sprintf("nice_katana failed for %s: %v", target, err), M_red)
				}
			}
		} else {
			logMsg(fmt.Sprintf("No passive URLs found for %s, skipping Katana", target), M_gray)
		}

		// STEP 3: Params runs only after Katana is fully done
		logMsg(fmt.Sprintf("[3/3] Running nice_params for %s", target), M_gray)
		if err := runBinary("./nice_params", "-u", target, "-d", paramsDir); err != nil {
			logMsg(fmt.Sprintf("nice_params failed for %s: %v", target, err), M_red)
		}

		// Aggregate results and run xssniper
		logMsg(fmt.Sprintf("Launching XSSniper for %s", target), M_cyan)

		jobFile := filepath.Join(globalOutputDir, fmt.Sprintf("job_%s.txt", safeURL+"_"+time.Now().Format("20060102150405")))
		paramFilePath := filepath.Join(paramsDir, hostname+"-param.txt")

		f, err := os.Create(jobFile)
		if err == nil {
			defer f.Close()
			f.WriteString(target + "\n")

			appendSafe := func(path string) {
				pFile, err := os.Open(path)
				if err != nil {
					return
				}
				defer pFile.Close()
				scanner := bufio.NewScanner(pFile)
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if line == "" {
						continue
					}
					if lURL, err := url.Parse(line); err == nil {
						lHost := lURL.Hostname()
						if lHost != rootDomain && !strings.HasSuffix(lHost, "."+rootDomain) {
							continue
						}
					} else {
						continue
					}
					if !utils.IsGoodURL(line) {
						continue
					}
					f.WriteString(line + "\n")
				}
			}

			if !noCrawl {
				appendSafe(passiveOutFile)
				appendSafe(katanaOutFile)
			}
		}

		args := []string{"-l", jobFile, "-p", paramFilePath, "-w", "3"}
		if isSingleTarget {
			args = append(args, "-u", target)
		}
		if skipSPA {
			args = append(args, "-skip-spa")
		}
		args = append(args, "-phase", fmt.Sprintf("%d", phase))

		runBinary("./xssniper", args...)

		markAsScanned(target)
	}
}
func main() {
	mode := flag.String("mode", "normal", "Scan mode: normal or fresh")
	inputFile := flag.String("i", "", "Input file with targets (skips API)")
	targetURL := flag.String("u", "", "Single target URL to scan")
	skipSPA := flag.Bool("skip-spa", true, "Skip SPA detection (if true, do not check for SPA)")
	noCrawl := flag.Bool("no-crawl", false, "Skip passive and katana crawling entirely")
	phase := flag.Int("phase", 4, "Pipeline phase to stop at (2, 3, or 4)")
	flag.Parse()

	// STEP 1: Capture terminal output to temp file explicitly via logWriter
	logFilePath := filepath.Join(os.TempDir(), fmt.Sprintf("scan_log_%d.txt", time.Now().Unix()))
	logFile, err := os.Create(logFilePath)
	if err == nil {
		logWriter = io.MultiWriter(os.Stdout, logFile)
		// Defer destruction and closing guaranteed on exit/panic LIFO style
		defer os.Remove(logFilePath)
		defer logFile.Close()
	}

	var errLogger error
	repLogger, errLogger = reporter.NewLogger("results/raw_findings.jsonl")
	if errLogger != nil {
		logMsg(fmt.Sprintf("reporter init failed: %v", errLogger), M_red)
		if logFile != nil {
			logFile.Close()
			os.Remove(logFilePath)
		}
		os.Exit(1)
	}
	startTime := time.Now()
	var newTargets []string
	isSingleTarget := false

	if *targetURL != "" {
		newTargets = []string{*targetURL}
		logMsg(fmt.Sprintf("Single target mode: %s", *targetURL), M_cyan)
		isSingleTarget = true
	} else {
		var rawTargets []string
		if *inputFile != "" {
			file, err := os.Open(*inputFile)
			if err != nil {
				logMsg(fmt.Sprintf("Error opening input file: %v", err), M_red)
				return
			}
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				if t := strings.TrimSpace(scanner.Text()); t != "" {
					rawTargets = append(rawTargets, t)
				}
			}
			file.Close()
		} else {
			rawTargets = fetchDataFromAPI(*mode)
		}
		if len(rawTargets) == 0 {
			return
		}

		if *mode == "fresh" {
			newTargets = rawTargets
		} else {
			newTargets = getNewTargetsOnly(rawTargets)
		}
	}

	if len(newTargets) == 0 {
		logMsg("No targets to process.", M_green)
		return
	}

	logMsg(fmt.Sprintf("Ready to process %d targets in %s mode.", len(newTargets), strings.ToUpper(*mode)), M_cyan)
	for _, target := range newTargets {
		processTarget(target, isSingleTarget, *skipSPA, *noCrawl, *phase)
	}

	mdPath := "results/TARGET_REPORT.md"
	if err := reporter.GenerateMarkdownReport("results/raw_findings.jsonl", mdPath); err != nil {
		logMsg(fmt.Sprintf("report generation failed: %v", err), M_red)
	}

	findings, _ := reporter.ReadFindings("results/raw_findings.jsonl")
	vulnCount := 0
	for _, f := range findings {
		if strings.EqualFold(f.Confidence, "HIGH") {
			vulnCount++
		}
	}

	reporter.PrintDashboard(reporter.DashboardStats{
		TargetsScanned:   len(newTargets),
		PassiveURLs:      countLinesInDir(filepath.Join(globalOutputDir, "passive")), // adjust if you track per-target totals instead
		ParamsDiscovered: len(findings),
		VulnsFound:       vulnCount,
		ReportPath:       mdPath,
		Elapsed:          time.Since(startTime),
	})

	// STEP 2 & 3: Attempt to upload to telegram before the file gets destroyed
	loadEnv()
	botToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	chatID := os.Getenv("TELEGRAM_CHAT_ID")

	if botToken != "" && chatID != "" {
		if logFile != nil {
			logFile.Sync() // Ensure OS buffer is flushed to disk prior to upload
		}

		caption := fmt.Sprintf("Mode: %s\nTargets: %d\nElapsed: %s\nVulns Found: %d",
			strings.ToUpper(*mode), len(newTargets), time.Since(startTime).Round(time.Second).String(), vulnCount)

		if err := sendTelegramDoc(botToken, chatID, logFilePath, caption); err != nil {
			logMsg(fmt.Sprintf("Failed to send log to Telegram: %v", err), M_red)
		} else {
			logMsg("Successfully sent log file to Telegram.", M_green)
		}
	}
}
