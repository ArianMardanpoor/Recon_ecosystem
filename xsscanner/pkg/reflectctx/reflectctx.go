package reflectctx

import (
	"bytes"
	"regexp"
	"strings"
)

type ContextType string

const (
	ContextJSString         ContextType = "js_string"          // inside <script>...</script>, reflected inside a JS string literal
	ContextHTMLAttrQuoted   ContextType = "html_attr_quoted"   // inside foo="..." or foo='...' outside <script>
	ContextHTMLAttrUnquoted ContextType = "html_attr_unquoted" // inside foo=... with no quotes
	ContextHTMLBody         ContextType = "html_body"          // between tags, in plain HTML text
	ContextUnknown          ContextType = "unknown"
)

type ReflectionContext struct {
	Type      ContextType
	QuoteChar byte // '"' or '\'' if applicable, 0 otherwise
}

// IsEscaped reports whether the byte at position idx in body is preceded
// by an odd number of consecutive backslashes (i.e. is escaped in a JS/JSON
// string literal sense). Only meaningful when ctx.Type == ContextJSString.
func IsEscaped(body []byte, idx int) bool {
	count := 0
	for i := idx - 1; i >= 0; i-- {
		if body[i] == '\\' {
			count++
		} else {
			break
		}
	}
	return count%2 != 0
}

// ClassifyContext analyzes the bytes surrounding canaryOffset to classify
// the reflection context.
func ClassifyContext(body []byte, canaryOffset int) ReflectionContext {
	if canaryOffset < 0 || canaryOffset >= len(body) {
		return ReflectionContext{Type: ContextUnknown}
	}

	// Bound the scan window backwards to avoid O(N) blowups
	startScan := canaryOffset - 500
	if startScan < 0 {
		startScan = 0
	}

	// OPTIMIZATION: Avoid allocating a full-body lowercase copy.
	// Only lower the bounded window we actually care about.
	windowBody := body[startScan:canaryOffset]
	lowerWindow := bytes.ToLower(windowBody)

	inScript := false
	lastScript := bytes.LastIndex(lowerWindow, []byte("<script"))

	if lastScript != -1 {
		lastScriptClose := bytes.LastIndex(lowerWindow, []byte("</script>"))
		if lastScriptClose < lastScript {
			// Ensure there's a closing script tag eventually after our canary
			forwardLimit := canaryOffset + 500
			if forwardLimit > len(body) {
				forwardLimit = len(body)
			}
			forwardWindow := bytes.ToLower(body[canaryOffset:forwardLimit])
			if bytes.Index(forwardWindow, []byte("</script>")) != -1 {
				inScript = true
			}
		}
		// Adjust offset relative to the original body for the backwards scan
		lastScript += startScan
	}

	if inScript {
		if lastScript > startScan {
			startScan = lastScript
		}
		// Scan backwards looking for nearest unescaped quote
		for i := canaryOffset - 1; i >= startScan; i-- {
			c := body[i]
			if c == '"' || c == '\'' || c == '`' {
				if !IsEscaped(body, i) {
					return ReflectionContext{
						Type:      ContextJSString,
						QuoteChar: c,
					}
				}
			}
		}
		return ReflectionContext{Type: ContextUnknown}
	}

	// 2. HTML context checks
	unquotedMatch := false
	j := canaryOffset - 1
	for j >= startScan && (body[j] == ' ' || body[j] == '\t') {
		j--
	}
	if j >= startScan && body[j] == '=' {
		unquotedMatch = true
	}

	// Scan backwards for structural boundaries or attribute openings
	for i := canaryOffset - 1; i >= startScan; i-- {
		c := body[i]

		if c == '>' {
			return ReflectionContext{Type: ContextHTMLBody}
		}

		if c == '<' {
			if unquotedMatch {
				return ReflectionContext{Type: ContextHTMLAttrUnquoted}
			}
			return ReflectionContext{Type: ContextUnknown}
		}

		if c == '"' || c == '\'' {
			k := i - 1
			for k >= startScan && (body[k] == ' ' || body[k] == '\t') {
				k--
			}

			if k >= startScan && body[k] == '=' {
				safe := true
				for m := i + 1; m < canaryOffset; m++ {
					mc := body[m]
					if mc == '<' || mc == '>' {
						safe = false
						break
					}
					// The character immediately before the canary is the injected
					// leading‑marker quote – it must not be treated as a closing quote.
					if mc == c && m != canaryOffset-1 {
						if m == 0 || body[m-1] != '\\' {
							safe = false
							break
						}
					}
				}
				if safe {
					return ReflectionContext{
						Type:      ContextHTMLAttrQuoted,
						QuoteChar: c,
					}
				}
			}
		}
	}

	if unquotedMatch {
		return ReflectionContext{Type: ContextHTMLAttrUnquoted}
	}

	return ReflectionContext{Type: ContextUnknown}
}

// VerifyBreakout inspects `body` for a reflected `canary` and
// determines whether the specific break-character markerChar actually escaped
// its surrounding context — as opposed to being reflected harmlessly inside
// a quoted/escaped value.
//
// markerChar is one of: '"', '\”, '<' (tag-open probes use '<').
// Returns (breakoutConfirmed bool, contextType ContextType).
func VerifyBreakout(body []byte, canary string, markerChar byte) (bool, ContextType) {
	canaryBytes := []byte(canary)
	canaryLen := len(canaryBytes)
	offset := 0

	for {
		idx := bytes.Index(body[offset:], canaryBytes)
		if idx == -1 {
			break
		}
		actualIdx := offset + idx
		ctx := ClassifyContext(body, actualIdx)

		if ctx.Type != ContextUnknown {
			match := false
			switch ctx.Type {
			case ContextHTMLAttrQuoted, ContextJSString:
				if markerChar == ctx.QuoteChar {
					isLeadingDoubled := false
					isTrailingDoubled := false
					var leadingQuoteIdx, trailingQuoteIdx int

					if actualIdx >= 2 && body[actualIdx-1] == ctx.QuoteChar && body[actualIdx-2] == ctx.QuoteChar {
						isLeadingDoubled = true
						leadingQuoteIdx = actualIdx - 2
					}

					end := actualIdx + canaryLen
					if end+1 < len(body) && body[end] == ctx.QuoteChar && body[end+1] == ctx.QuoteChar {
						isTrailingDoubled = true
						trailingQuoteIdx = end
					}

					if isLeadingDoubled || isTrailingDoubled {
						match = true
						if ctx.Type == ContextJSString {
							if isLeadingDoubled && IsEscaped(body, leadingQuoteIdx) {
								match = false
							}
							if isTrailingDoubled && IsEscaped(body, trailingQuoteIdx) {
								match = false
							}
						}
					}
				}
			case ContextHTMLAttrUnquoted:
				if markerChar == '<' {
					match = true
				} else {
					isWhitespaceOrGT := func(b byte) bool {
						return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '>'
					}
					if actualIdx > 0 && isWhitespaceOrGT(body[actualIdx-1]) {
						match = true
					} else {
						end := actualIdx + canaryLen
						if end < len(body) && isWhitespaceOrGT(body[end]) {
							match = true
						}
					}
				}
			case ContextHTMLBody:
				if markerChar == '<' {
					if actualIdx >= 3 && string(body[actualIdx-3:actualIdx]) == "<b9" {
						match = true
						if actualIdx >= 7 && strings.ToLower(string(body[actualIdx-7:actualIdx-3])) == "&lt;" {
							match = false
						}
					} else {
						end := actualIdx + canaryLen
						if end < len(body) && body[end] == '<' {
							match = true
						}
					}
				}
			}

			if match {
				return true, ctx.Type
			}
		}

		// Advance offset to check for the next reflection of the canary
		offset = actualIdx + canaryLen
	}

	return false, ContextUnknown
}

func ExtractCanary(full string) string {
	// bareCanaryRe matches either "x9" + 3 letters or "x9canary" + 3 letters
	bareCanaryRe := regexp.MustCompile(`x9(?:canary)?[a-z]{3}`)
	match := bareCanaryRe.FindString(full)
	if match != "" {
		return match
	}
	// fallback: return the full string; this preserves existing behaviour
	// for probe mode or unexpected cases.
	return full
}
