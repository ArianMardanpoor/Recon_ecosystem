// Package reporter provides a unified findings pipeline for the recon/XSS toolchain:
//   1. JSONL append log      -> results/raw_findings.jsonl   (machine-readable)
//   2. Markdown report       -> results/TARGET_REPORT.md     (human-readable)
//   3. ASCII stats dashboard -> stdout at end of run
package reporter

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ─── Schema ─────────────────────────────────────────────────────────────────

type Context struct {
	Location     string   `json:"location"`
	AllowedChars []string `json:"allowed_chars"`
	StatusCode   int      `json:"status_code"`
}

type Finding struct {
	Timestamp           string  `json:"timestamp"`
	RootDomain          string  `json:"root_domain"`
	URL                 string  `json:"url"`
	VulnerableParameter string  `json:"vulnerable_parameter"`
	DiscoverySource     string  `json:"discovery_source"` // katana, x8, fallparams, x9, dom_sink, xssniper...
	Confidence          string  `json:"confidence"`       // HIGH / MEDIUM / LOW
	ReflectionType      string  `json:"reflection_type"`  // source_reflection, dom_sink_injection, candidate...
	Context             Context `json:"context"`
}

// NewFinding is a convenience constructor that stamps the current time.
func NewFinding(rootDomain, url, param, source, confidence, reflType string, ctx Context) Finding {
	return Finding{
		Timestamp:           time.Now().Format(time.RFC3339),
		RootDomain:          rootDomain,
		URL:                 url,
		VulnerableParameter: param,
		DiscoverySource:     source,
		Confidence:          strings.ToUpper(confidence),
		ReflectionType:      reflType,
		Context:             ctx,
	}
}

// ─── Logger (JSONL writer, safe for concurrent use across goroutines/tools) ─

type Logger struct {
	mu   sync.Mutex
	path string
}

// NewLogger opens (or creates) the JSONL file for appending and returns a Logger.
// Call this once per process; safe to share across goroutines via the same *Logger.
func NewLogger(path string) (*Logger, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("reporter: mkdir %s: %w", dir, err)
		}
	}
	return &Logger{path: path}, nil
}

// Log appends a single Finding as one JSON line. Safe for concurrent calls.
func (l *Logger) Log(f Finding) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	fh, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("reporter: open %s: %w", l.path, err)
	}
	defer fh.Close()

	b, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("reporter: marshal finding: %w", err)
	}
	if _, err := fh.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("reporter: write finding: %w", err)
	}
	return nil
}

// LogFromExternalTool is a helper for logging findings emitted by a subprocess
// (e.g. a Python dom_sink_checker) that prints one JSON-per-line Finding to stdout.
// Call this per captured line from the subprocess's output.
func (l *Logger) LogFromExternalTool(line string) error {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	var f Finding
	if err := json.Unmarshal([]byte(line), &f); err != nil {
		return fmt.Errorf("reporter: invalid finding line from external tool: %w", err)
	}
	return l.Log(f)
}

// ─── Reading back all findings ──────────────────────────────────────────────

func ReadFindings(jsonlPath string) ([]Finding, error) {
	fh, err := os.Open(jsonlPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer fh.Close()

	var out []Finding
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var f Finding
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			continue // skip malformed lines rather than aborting the whole report
		}
		out = append(out, f)
	}
	return out, sc.Err()
}

// isHigh decides whether a finding belongs in the "High Confidence" bucket.
func isHigh(f Finding) bool {
	if strings.EqualFold(f.Confidence, "HIGH") {
		return true
	}
	rt := strings.ToLower(f.ReflectionType)
	return strings.Contains(rt, "dom_sink_injection") || strings.Contains(rt, "source_reflection")
}

// ─── Markdown report ────────────────────────────────────────────────────────

// GenerateMarkdownReport reads jsonlPath and writes a grouped, table-based
// markdown report to mdPath.
func GenerateMarkdownReport(jsonlPath, mdPath string) error {
	findings, err := ReadFindings(jsonlPath)
	if err != nil {
		return fmt.Errorf("reporter: read findings: %w", err)
	}

	var high, medium []Finding
	for _, f := range findings {
		if isHigh(f) {
			high = append(high, f)
		} else {
			medium = append(medium, f)
		}
	}

	sortFn := func(s []Finding) {
		sort.Slice(s, func(i, j int) bool {
			if s[i].RootDomain != s[j].RootDomain {
				return s[i].RootDomain < s[j].RootDomain
			}
			return s[i].Timestamp < s[j].Timestamp
		})
	}
	sortFn(high)
	sortFn(medium)

	var b strings.Builder
	b.WriteString("# 🎯 Vulnerability Scan Report\n\n")
	b.WriteString(fmt.Sprintf("_Generated: %s_\n\n", time.Now().Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("**Total findings:** %d  |  **High confidence:** %d  |  **Medium/Low:** %d\n\n",
		len(findings), len(high), len(medium)))
	b.WriteString("---\n\n")

	writeTable := func(title, emptyMsg string, rows []Finding) {
		b.WriteString("## " + title + "\n\n")
		if len(rows) == 0 {
			b.WriteString("_" + emptyMsg + "_\n\n")
			return
		}
		b.WriteString("| URL | Parameter | Context / Sink | Source |\n")
		b.WriteString("|---|---|---|---|\n")
		for _, f := range rows {
			ctxDesc := f.Context.Location
			if ctxDesc == "" {
				ctxDesc = f.ReflectionType
			}
			if len(f.Context.AllowedChars) > 0 {
				ctxDesc += fmt.Sprintf(" (chars: `%s`)", strings.Join(f.Context.AllowedChars, ""))
			}
			param := f.VulnerableParameter
			if param == "" {
				param = "—"
			}
			// Escape pipe characters so the URL/context can't break the table.
			url := strings.ReplaceAll(f.URL, "|", "\\|")
			ctxDesc = strings.ReplaceAll(ctxDesc, "|", "\\|")
			b.WriteString(fmt.Sprintf("| [%s](%s) | `%s` | %s | %s |\n",
				f.RootDomain, url, param, ctxDesc, f.DiscoverySource))
		}
		b.WriteString("\n")
	}

	writeTable("🔥 High Confidence Targets", "No confirmed reflections or DOM sinks yet.", high)
	writeTable("🔍 Medium/Low Confidence Targets", "No candidate parameters recorded yet.", medium)

	if err := os.MkdirAll(filepath.Dir(mdPath), 0755); err != nil {
		return fmt.Errorf("reporter: mkdir for report: %w", err)
	}
	if err := os.WriteFile(mdPath, []byte(b.String()), 0644); err != nil {
		return fmt.Errorf("reporter: write report: %w", err)
	}
	return nil
}

// ─── Dashboard ───────────────────────────────────────────────────────────────

type DashboardStats struct {
	TargetsScanned   int
	PassiveURLs      int
	ParamsDiscovered int
	VulnsFound       int // canary-reflected / confirmed
	ReportPath       string
	Elapsed         time.Duration
}

// PrintDashboard renders a compact ASCII summary box to stdout.
func PrintDashboard(s DashboardStats) {
	const width = 56
	line := func(label string, value interface{}) string {
		content := fmt.Sprintf(" %-30s %-21v", label, value)
		if len(content) > width-2 {
			content = content[:width-2]
		}
		return "║" + content + strings.Repeat(" ", width-2-len(content)) + "║"
	}

	top := "╔" + strings.Repeat("═", width-2) + "╗"
	mid := "╠" + strings.Repeat("═", width-2) + "╣"
	bot := "╚" + strings.Repeat("═", width-2) + "╝"

	fmt.Println()
	fmt.Println(top)
	fmt.Println("║" + centre(" SCAN SUMMARY DASHBOARD ", width-2) + "║")
	fmt.Println(mid)
	fmt.Println(line("Targets Scanned:", s.TargetsScanned))
	fmt.Println(line("Passive URLs Extracted:", s.PassiveURLs))
	fmt.Println(line("Parameters Discovered:", s.ParamsDiscovered))
	fmt.Println(line("Potential Vulns Found:", s.VulnsFound))
	fmt.Println(line("Elapsed:", s.Elapsed.Round(time.Second)))
	fmt.Println(mid)
	fmt.Println(line("Report:", s.ReportPath))
	fmt.Println(bot)
	fmt.Println()
}

func centre(s string, width int) string {
	if len(s) >= width {
		return s[:width]
	}
	padTotal := width - len(s)
	left := padTotal / 2
	right := padTotal - left
	return strings.Repeat(" ", left) + s + strings.Repeat(" ", right)
}
