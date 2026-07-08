// FILE: x9.go — MODIFIED
// Changes:
// - Added -strict flag (default false).
// - When strict=true, only use parameters present in the URL and from -p file;
//   defaultParams are NOT added.
// - If strict=true and URL has no query params, skip and print to stderr.

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"sort"
	"strings"

	"reconpipeline/pkg/reporter"
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
	var letters = []rune("abcdefghijklmnopqrstuvwxyz")
	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}

func getBreakPayloads() []string {
	prefix := "x9" + randomString(3)
	return []string{
		prefix + "'",
		prefix + "\"",
		prefix + "`",
		prefix + "<",
		prefix + ";",
		prefix + "{{",
	}
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

// getAllParams now accepts a 'strict' flag.
// When strict=true, defaultParams are NOT added; only original params and those from paramFile are used.
func getAllParams(originalParams map[string]string, paramFile string, probeMode bool, strict bool) []string {
	allParamsMap := make(map[string]bool)
	for k := range originalParams {
		allParamsMap[k] = true
	}

	// Only add defaultParams if strict is false and (probeMode or no original params)
	if !strict && (probeMode || len(allParamsMap) == 0) {
		for _, p := range defaultParams {
			allParamsMap[p] = true
		}
	}

	if paramFile != "" {
		file, err := os.Open(paramFile)
		if err == nil {
			sc := bufio.NewScanner(file)
			for sc.Scan() {
				p := strings.TrimSpace(sc.Text())
				if p != "" {
					allParamsMap[p] = true
				}
			}
			file.Close()
		}
	}
	result := make([]string, 0, len(allParamsMap))
	for p := range allParamsMap {
		result = append(result, p)
	}
	sort.Strings(result)
	return result
}

func main() {
	var (
		inputFile  string
		paramFile  string
		outputBase string
		singleURL  string
		probeMode  bool
		jsonMode   bool
		headerMode bool
		domMode    bool
		strictMode bool // NEW
	)

	flag.StringVar(&inputFile, "i", "", "File containing URLs")
	flag.StringVar(&singleURL, "u", "", "Single URL to test")
	flag.StringVar(&paramFile, "p", "", "Custom parameters file")
	flag.StringVar(&outputBase, "o", "x9_output", "Output base filename (suffixes will be added)")
	flag.BoolVar(&probeMode, "probe", false, "Enable canary probe mode")
	flag.BoolVar(&jsonMode, "json", false, "Enable JSON body generation")
	flag.BoolVar(&headerMode, "headers", false, "Enable Header injection mode")
	flag.BoolVar(&domMode, "dom", false, "Enable DOM fragment injection mode")
	flag.BoolVar(&strictMode, "strict", false, "Only use existing parameters, no default list") // NEW
	flag.Parse()
	repLogger, err := reporter.NewLogger("results/raw_findings.jsonl")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[x9] reporter init failed: %v\n", err)
		os.Exit(1)
	}
	if inputFile == "" && singleURL == "" {
		flag.Usage()
		os.Exit(1)
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

	var fJson, fHeader, fDomCanary, fDomAttack *os.File
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

	for _, raw := range rawURLs {
		base, err := parseURL(raw)
		if err != nil {
			continue
		}

		// If strict mode is enabled and the URL has no query parameters, skip it.
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

		// Pass strictMode to getAllParams
		allParams := getAllParams(base.Params, paramFile, probeMode, strictMode)

		for _, payload := range payloads {
			// 1. Standard URL Parameters
			for _, p := range allParams {
				newParams := make(map[string]string)
				for k, v := range base.Params {
					newParams[k] = v
				}
				newParams[p] = payload
				generatedURL := buildURL(base, newParams)
				fmt.Fprintln(fGet, generatedURL)
				repLogger.Log(reporter.NewFinding(
					base.Host, generatedURL, p, "x9", "LOW", "candidate_generated",
					reporter.Context{Location: "query parameter"},
				))
			}

			// 2. JSON Body Mode
			if jsonMode && fJson != nil {
				jsonData := make(map[string]string)
				for _, p := range allParams {
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
				tempBase := *base
				tempBase.Fragment = payload
				// buildURL correctly preserves all parameters from base.Params
				urlWithFragment := buildURL(&tempBase, base.Params)
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
		}
	}
}
