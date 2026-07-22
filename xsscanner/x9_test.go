package main

import (
	"testing"

	"reconpipeline/pkg/reflectctx"
)

func TestVerifyContextBreakout(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		canary     string
		markerChar byte
		wantConf   bool
		wantCtx    reflectctx.ContextType
	}{
		{
			name:       "HTML attribute, doubled quote present -> confirmed true",
			body:       `<html><body><input value="""CANARY"></body></html>`,
			canary:     "CANARY",
			markerChar: '"',
			wantConf:   true,
			wantCtx:    reflectctx.ContextHTMLAttrQuoted,
		},
		{
			name:       "HTML attribute, quote reflected but NOT doubled -> confirmed false",
			body:       `<input value="prefix\"CANARY">`,
			canary:     "CANARY",
			markerChar: '"',
			wantConf:   false,
			wantCtx:    reflectctx.ContextHTMLAttrQuoted,
		},
		{
			name:       "JS string context, doubled quote present but preceded by backslash (escaped) -> confirmed false",
			// The three backslashes stringify to 3 literal '\', so count=3 (escaped)
			body:       `<script>var a = "prefix\\\"\"CANARY";</script>`, 
			canary:     "CANARY",
			markerChar: '"',
			wantConf:   false,
			wantCtx:    reflectctx.ContextJSString,
		},
		{
			name:       "JS string context, doubled quote present, NOT escaped -> confirmed true",
			// Preceded by 'x' instead of '\', so count=0 (not escaped)
			body:       `<script>var a = "prefix""CANARY";</script>`, 
			canary:     "CANARY",
			markerChar: '"',
			wantConf:   true,
			wantCtx:    reflectctx.ContextJSString,
		},
		{
			name:       "Tag body context with raw <b9+canary present -> confirmed true",
			body:       `<div><b9CANARY</div>`,
			canary:     "CANARY",
			markerChar: '<',
			wantConf:   true,
			wantCtx:    reflectctx.ContextHTMLBody,
		},
		{
			name:       "Tag body context with &lt;b9+canary (HTML-entity encoded) -> confirmed false",
			body:       `<div>&lt;<b9CANARY</div>`,
			canary:     "CANARY",
			markerChar: '<',
			wantConf:   false,
			wantCtx:    reflectctx.ContextHTMLBody,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotConf, gotCtx := VerifyContextBreakout([]byte(tt.body), tt.canary, tt.markerChar)
			if gotConf != tt.wantConf {
				t.Errorf("VerifyContextBreakout() conf = %v, want %v", gotConf, tt.wantConf)
			}
			if gotCtx != tt.wantCtx {
				t.Errorf("VerifyContextBreakout() ctx = %v, want %v", gotCtx, tt.wantCtx)
			}
		})
	}
}