package main

import (
	"regexp"
	"testing"

	"reconpipeline/pkg/reflectctx"
)

func TestVerifyBreakoutIntegration(t *testing.T) {
	// The payload we sent: x9canary"
	payload := "x9canary\""
	markerChar := byte('"')

	// Scenario: False Positive in the OLD substring/regex logic.
	// The server safely escapes the quote using a backslash inside a JS string block.
	// Old regex `x9[a-z]{3}['"\`;<{]` or simple `strings.Contains` would blind-match
	// `x9canary\"` because it technically contains the raw string `x9canary"`.
	simulatedResponseBody := []byte(`<script>
		var search_query = "x9canary\"";
		console.log("Searching for: " + search_query);
	</script>`)

	// 1. Prove the OLD logic fails (False Positive)
	oldRegex := regexp.MustCompile(`x9[a-z]{3}['"\` + "`" + `\;<{]`)
	if !oldRegex.Match(simulatedResponseBody) {
		t.Fatal("Expected old regex to fail by returning true (false positive), but it returned false.")
	}

	// 2. Prove the NEW logic succeeds (Correctly identifies escaped context)
	isConfirmed, ctxType := reflectctx.VerifyBreakout(simulatedResponseBody, payload, markerChar)

	if isConfirmed {
		t.Errorf("New logic failed: incorrectly confirmed an escaped JS string payload. Context detected: %s", ctxType)
	}

	if ctxType != reflectctx.ContextJSString {
		t.Errorf("Expected context to be js_string, got %s", ctxType)
	}
}
