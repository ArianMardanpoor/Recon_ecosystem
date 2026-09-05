package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"

	"reconpipeline/pkg/reporter"
)

var (
	rxNumeric = regexp.MustCompile(`^[0-9]+$`)
	rxAlnum   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,20}$`)
)

type Stats struct {
	TotalURLs  int
	ByStrategy map[string]int
	ByBase     map[string]int
}

func newStats() *Stats {
	return &Stats{
		ByStrategy: make(map[string]int),
		ByBase:     make(map[string]int),
	}
}

var defaultParams = []string{
	"q", "s", "search", "id", "lang", "keyword", "query", "page",
	"keywords", "year", "view", "email", "type", "name", "p", "month",
	"image", "list_type", "url", "terms", "categoryid", "key", "login",
	"begindate", "enddate", "d", "redirect_uri", "currentURL", "callback",
	"debug", "test", "redirect", "src", "source", "file", "path",
	"next", "return", "return_url", "returnUrl", "continue", "to", "goto", "callback",
	"checkout_url", "dest", "destination", "redir", "out", "view", "from_url",
	"message", "template",
}

var targetHeaders = []string{
	"User-Agent",
	"Referer",
	"X-Forwarded-For",
	"Origin",
	"X-Real-IP",
	"Client-IP",
	"X-Forwarded-Host",
	"X-Host",
}

func randomString(n int) string {
	return randomStringFrom("abcdefghijklmnopqrstuvwxyz", n)
}

func randomStringFrom(charset string, n int) string {
	letters := []rune(charset)
	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}

func getBreakPayloads() []string {
	prefix := "x9" + randomString(3)
	return []string{
		prefix + "'" + randomString(6),
		prefix + "\"" + randomString(6),
		prefix + "</test",
	}
}

func mutateSiblingValue(orig string) string {
	l := len(orig)
	if l == 0 {
		return "x9m"
	}
	if rxNumeric.MatchString(orig) {
		return randomStringFrom("0123456789", l)
	}
	if rxAlnum.MatchString(orig) {
		return randomStringFrom("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", l)
	}
	// Fallback for complex/long strings
	if l > 50 {
		l = 50
	}
	return randomStringFrom("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", l)
}

type ParsedURL struct {
	Scheme   string
	Host     string
	Path     string
	RawQuery string
	Fragment string
	Params   map[string]string
}

func parseURL(rawURL string) (*ParsedURL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	parsed := &ParsedURL{
		Scheme:   u.Scheme,
		Host:     u.Host,
		Path:     u.Path,
		RawQuery: u.RawQuery,
		Fragment: u.Fragment,
		Params:   make(map[string]string),
	}
	for k, v := range u.Query() {
		if len(v) > 0 {
			parsed.Params[k] = v[0]
		}
	}
	return parsed, nil
}

func buildURL(base *ParsedURL, params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(params[k]))
	}
	u := &url.URL{
		Scheme:   base.Scheme,
		Host:     base.Host,
		Path:     base.Path,
		RawQuery: strings.Join(parts, "&"),
		Fragment: base.Fragment,
	}
	return u.String()
}

func buildURLSafe(base *ParsedURL, params map[string]string) (string, bool) {
	constructedURL := buildURL(base, params)

	parsed, err := parseURL(constructedURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] buildURLSafe failed to parse constructed URL: %v\n", err)
		return "", false
	}

	if parsed.Path != base.Path {
		baseStr := base.Scheme + "://" + base.Host + base.Path
		if base.RawQuery != "" {
			baseStr += "?" + base.RawQuery
		}
		if base.Fragment != "" {
			baseStr += "#" + base.Fragment
		}

		fmt.Fprintf(os.Stderr, "[ERROR] buildURL path mismatch: expected path=%q got path=%q (base=%q)\n", base.Path, parsed.Path, baseStr)
		return "", false
	}

	return constructedURL, true
}

func main() {
	var (
		inputFile    string
		paramFile    string
		outputBase   string
		singleURL    string
		probeMode    bool
		jsonMode     bool
		headerMode   bool
		domMode      bool
		strictMode   bool
		pathInject   bool
		encodingType string
		valStrategy  string
		paramModeStr string
	)

	flag.StringVar(&inputFile, "i", "", "File containing URLs")
	flag.StringVar(&singleURL, "u", "", "Single URL to test")
	flag.StringVar(&paramFile, "p", "", "Custom parameters file")
	flag.StringVar(&outputBase, "o", "x9_output", "Output base filename (suffixes will be added)")
	flag.BoolVar(&probeMode, "probe", false, "Enable canary probe mode")
	flag.BoolVar(&jsonMode, "json", false, "Enable JSON body generation")
	flag.BoolVar(&headerMode, "headers", false, "Enable Header injection mode")
	flag.BoolVar(&domMode, "dom", false, "Enable DOM fragment injection mode")
	flag.BoolVar(&strictMode, "strict", false, "Only use existing parameters, no default list")
	flag.BoolVar(&pathInject, "path-inject", false, "Inject payloads directly into the URL path as a new segment")
	flag.StringVar(&encodingType, "encoding", "single", "Encoding type: 'single' or 'double'")
	flag.StringVar(&valStrategy, "value-strategy", "replace", "Value strategy: 'replace' or 'append'")
	flag.StringVar(&paramModeStr, "param-mode", "baseline,discovered", "Modes: baseline, discovered, mutate-siblings, or all")
	flag.Parse()

	// Parse and validate param-mode
	var activeModes []string
	modesMap := make(map[string]bool)
	hasAll := false

	for _, part := range strings.Split(paramModeStr, ",") {
		part = strings.TrimSpace(part)
		if part == "all" {
			hasAll = true
			break
		}
		if part != "baseline" && part != "discovered" && part != "mutate-siblings" {
			fmt.Fprintf(os.Stderr, "[ERROR] Invalid param-mode '%s'. Allowed: baseline, discovered, mutate-siblings, all\n", part)
			os.Exit(1)
		}
		if !modesMap[part] {
			modesMap[part] = true
			activeModes = append(activeModes, part)
		}
	}

	if hasAll {
		activeModes = []string{"baseline", "discovered", "mutate-siblings"}
	}
	fmt.Fprintf(os.Stderr, "[x9] param-mode active: %s\n", strings.Join(activeModes, ", "))

	repLogger, err := reporter.NewLogger("results/raw_findings.jsonl")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[x9] reporter init failed: %v\n", err)
		os.Exit(1)
	}
	if inputFile == "" && singleURL == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Pre-load param file contents once
	var fileParams []string
	if paramFile != "" {
		if file, err := os.Open(paramFile); err == nil {
			sc := bufio.NewScanner(file)
			for sc.Scan() {
				if p := strings.TrimSpace(sc.Text()); p != "" {
					fileParams = append(fileParams, p)
				}
			}
			file.Close()
		}
	}

	var rawURLs []string
	if singleURL != "" {
		rawURLs = append(rawURLs, singleURL)
	}
	if inputFile != "" {
		file, err := os.Open(inputFile)
		if err == nil {
			sc := bufio.NewScanner(file)
			for sc.Scan() {
				if line := strings.TrimSpace(sc.Text()); line != "" {
					rawURLs = append(rawURLs, line)
				}
			}
			file.Close()
		}
	}

	fGet, _ := os.Create(outputBase + ".get")
	defer fGet.Close()

	var fJson, fHeader, fDomCanary, fDomAttack, fPath *os.File
	if jsonMode {
		fJson, _ = os.Create(outputBase + ".json")
		defer fJson.Close()
	}
	if headerMode {
		fHeader, _ = os.Create(outputBase + ".header")
		defer fHeader.Close()
	}
	if domMode {
		fDomCanary, _ = os.Create(outputBase + ".dom.canary")
		defer fDomCanary.Close()
		fDomAttack, _ = os.Create(outputBase + ".dom.attack")
		defer fDomAttack.Close()
	}
	if pathInject {
		fPath, _ = os.Create(outputBase + ".path")
		defer fPath.Close()
	}

	// Determine encodings to run
	encodings := []string{"single"}
	if encodingType == "double" {
		encodings = append(encodings, "double")
	}

	for _, raw := range rawURLs {
		base, err := parseURL(raw)
		if err != nil {
			continue
		}

		if strictMode && len(base.Params) == 0 {
			fmt.Fprintf(os.Stderr, "[SKIP] no params in URL, strict mode active: %s\n", raw)
			continue
		}

		var payloads []string
		if probeMode {
			payloads = []string{"x9canary" + randomString(3)}
		} else {
			payloads = getBreakPayloads()
		}

		// Build baseline targets
		baselineMap := make(map[string]bool)
		for k := range base.Params {
			baselineMap[k] = true
		}
		if !strictMode && (probeMode || len(baselineMap) == 0) {
			for _, p := range defaultParams {
				baselineMap[p] = true
			}
		}
		var baselineTargets []string
		for k := range baselineMap {
			baselineTargets = append(baselineTargets, k)
		}
		sort.Strings(baselineTargets)

		// Build discovered targets
		discoveredMap := make(map[string]bool)
		for _, k := range baselineTargets {
			discoveredMap[k] = true
		}
		for _, p := range fileParams {
			discoveredMap[p] = true
		}
		var discoveredTargets []string
		for k := range discoveredMap {
			discoveredTargets = append(discoveredTargets, k)
		}
		sort.Strings(discoveredTargets)

		for _, payload := range payloads {
			// 1. Standard URL Parameters (GET) with Param Modes
			for _, mode := range activeModes {
				currentTargets := baselineTargets
				if mode == "discovered" {
					currentTargets = discoveredTargets
				}

				for _, p := range currentTargets {
					for _, enc := range encodings {
						newParams := make(map[string]string)

						// Populate sibling parameters
						for k, v := range base.Params {
							if k == p {
								continue // Handled below
							}
							if mode == "mutate-siblings" {
								newParams[k] = mutateSiblingValue(v)
							} else {
								newParams[k] = v
							}
						}

						// Prepare payload encoding & value strategy
						activePayload := payload
						if enc == "double" {
							activePayload = url.QueryEscape(payload)
						}

						injectedVal := activePayload
						if valStrategy == "append" {
							injectedVal = base.Params[p] + activePayload
						}
						newParams[p] = injectedVal

						generatedURL, ok := buildURLSafe(base, newParams)
						if !ok {
							continue
						}

						fmt.Fprintln(fGet, generatedURL)
						repLogger.Log(reporter.NewFinding(
							base.Host, generatedURL, p, "x9", "LOW", "candidate_generated",
							reporter.Context{Location: fmt.Sprintf("query parameter (mode: %s)", mode)},
						))
					}
				}
			}

			// 2. JSON Body Mode (Uses baselineTargets)
			if jsonMode && fJson != nil {
				jsonData := make(map[string]string)
				for _, p := range baselineTargets {
					jsonData[p] = payload
				}
				jsonStr, _ := json.Marshal(jsonData)
				fmt.Fprintf(fJson, "%s://%s%s|%s\n", base.Scheme, base.Host, base.Path, string(jsonStr))
			}

			// 3. Header Injection Mode
			if headerMode && fHeader != nil {
				for _, h := range targetHeaders {
					fmt.Fprintf(fHeader, "%s|%s:%s\n", raw, h, payload)
				}
			}

			// 4. DOM Fragment Injection Mode
			if domMode {
				domURL := &url.URL{
					Scheme:   base.Scheme,
					Host:     base.Host,
					Path:     base.Path,
					RawQuery: base.RawQuery,
					Fragment: payload,
				}
				urlWithFragment := domURL.String()

				if probeMode {
					if fDomCanary != nil {
						fmt.Fprintln(fDomCanary, urlWithFragment)
					}
				} else {
					if fDomAttack != nil {
						fmt.Fprintln(fDomAttack, urlWithFragment)
					}
				}
			}

			// 5. Path Injection Mode
			if pathInject && fPath != nil {
				newPath := strings.TrimRight(base.Path, "/") + "/" + payload

				pathURL := fmt.Sprintf("%s://%s%s", base.Scheme, base.Host, newPath)
				if base.RawQuery != "" {
					pathURL += "?" + base.RawQuery
				}
				if base.Fragment != "" {
					pathURL += "#" + base.Fragment
				}

				fmt.Fprintln(fPath, pathURL)
			}
		}
	}
}
