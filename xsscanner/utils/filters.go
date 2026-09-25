// utils/filters.go
package utils

import (
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"
)

var (
	reNumeric  = regexp.MustCompile(`^\d+$`)
	reSemver   = regexp.MustCompile(`^\d+\.\d+(\.\d+)?$`)
	reCSSValue = regexp.MustCompile(`^\d+(px|em|rem|vh|vw|ms|fr|%)$`)
	reUpper    = regexp.MustCompile(`[A-Z]`)
	reDigit    = regexp.MustCompile(`[0-9]`)
	reLower    = regexp.MustCompile(`[a-z]`)
)

var blockedExtensions = []string{
	".json", ".js", ".fnt", ".ogg", ".css", ".jpg", ".jpeg", ".png", ".svg",
	".img", ".gif", ".exe", ".mp4", ".flv", ".pdf", ".doc", ".ogv", ".webm",
	".wmv", ".webp", ".mov", ".mp3", ".m4a", ".m4p", ".ppt", ".pptx", ".scss",
	".tif", ".tiff", ".ttf", ".otf", ".woff", ".woff2", ".bmp", ".ico", ".eot",
	".htc", ".swf", ".rtf", ".image", ".rf", ".txt", ".xml", ".zip",
}

func isHighEntropySegment(s string) bool {
	if len(s) < 40 {
		return false
	}
	return reUpper.MatchString(s) && reDigit.MatchString(s) && reLower.MatchString(s)
}

// IsGoodURL filters out static assets, numeric/semver/CSS-like/high-entropy segments.
func IsGoodURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	path := strings.ToLower(parsed.Path)
	for _, ext := range blockedExtensions {
		if strings.HasSuffix(path, ext) {
			return false
		}
	}

	pathSegments := strings.Split(strings.Trim(path, "/"), "/")
	if len(pathSegments) == 0 || (len(pathSegments) == 1 && pathSegments[0] == "") {
		return true
	}
	lastSegment := pathSegments[len(pathSegments)-1]

	if reNumeric.MatchString(lastSegment) {
		return false
	}
	if reSemver.MatchString(lastSegment) {
		return false
	}
	if strings.Count(lastSegment, ".") >= 1 && len(pathSegments) <= 2 {
		return false
	}
	if reCSSValue.MatchString(lastSegment) {
		return false
	}
	for _, seg := range pathSegments {
		if isHighEntropySegment(seg) {
			return false
		}
	}

	return true
}

// ExtractRootDomain returns the true eTLD+1 (registrable domain) using the
// public suffix list, so multi-part TLDs (co.uk, com.br, co.jp, github.io...)
// are handled correctly instead of naively taking the last two labels.
func ExtractRootDomain(hostname string) string {
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	etld1, err := publicsuffix.EffectiveTLDPlusOne(hostname)
	if err != nil {
		// Not eligible (e.g. bare IP, single-label host, unknown suffix) — fall back to raw hostname.
		return hostname
	}
	return etld1
}
