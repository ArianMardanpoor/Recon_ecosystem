// pkg/spadetect/spadetect.go
package spadetect

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"unicode"

	"reconpipeline/pkg/ratelimit"
)

// IsSPA performs a lightweight GET and checks for SPA markers
// and visible-text-ratio heuristics.
func IsSPA(targetURL string) bool {
	ratelimit.Acquire(targetURL)
	client := ratelimit.GetHTTPClient(targetURL)
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; xssniper)")
	
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	body := string(bodyBytes)

	markers := []string{
		`<div id="root"`,
		`<div id="app"`,
		`__NEXT_DATA__`,
		`window.__INITIAL_STATE__`,
		`ReactDOM.render`,
		`ng-version=`,
		`data-reactroot`,
	}
	for _, m := range markers {
		if strings.Contains(body, m) {
			return true
		}
	}

	reScript := regexp.MustCompile(`(?s)<script[^>]*>.*?</script>`)
	reStyle := regexp.MustCompile(`(?s)<style[^>]*>.*?</style>`)
	clean := reScript.ReplaceAllString(body, "")
	clean = reStyle.ReplaceAllString(clean, "")
	
	reTag := regexp.MustCompile(`<[^>]*>`)
	text := reTag.ReplaceAllString(clean, " ")
	
	visibleCount := 0
	for _, ch := range text {
		if !unicode.IsSpace(ch) {
			visibleCount++
		}
	}
	if visibleCount < 500 {
		return true
	}

	xPoweredBy := resp.Header.Get("x-powered-by")
	if strings.Contains(strings.ToLower(xPoweredBy), "next.js") && visibleCount < 500 {
		return true
	}
	if strings.Contains(strings.ToLower(xPoweredBy), "express") && visibleCount < 500 {
		return true
	}

	return false
}