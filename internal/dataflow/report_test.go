package dataflow

import (
	"strings"
	"testing"
)

func TestCapitalizeFirst(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "empty string", input: "", expected: ""},
		{name: "single lowercase char", input: "a", expected: "A"},
		{name: "single uppercase char", input: "A", expected: "A"},
		{name: "normal lowercase string", input: "hello", expected: "Hello"},
		{name: "already capitalized", input: "Hello", expected: "Hello"},
		{name: "all uppercase", input: "HELLO", expected: "HELLO"},
		{name: "unicode string", input: "über", expected: "Über"},
		{name: "numeric prefix", input: "123abc", expected: "123abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := capitalizeFirst(tt.input)
			if result != tt.expected {
				t.Errorf("capitalizeFirst(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestEscapeMarkdownInline(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "clean string", input: "hello world", expected: "hello world"},
		{name: "backticks", input: "use `code` here", expected: "use \\`code\\` here"},
		{name: "pipes", input: "col1 | col2", expected: "col1 \\| col2"},
		{name: "asterisks", input: "*bold*", expected: "\\*bold\\*"},
		{name: "underscores", input: "_italic_", expected: "\\_italic\\_"},
		{name: "brackets", input: "[link](url)", expected: "\\[link\\]\\(url\\)"},
		{name: "hash", input: "# heading", expected: "\\# heading"},
		{name: "angle brackets", input: "<script>", expected: "&lt;script&gt;"},
		{name: "newlines and tabs", input: "a\n\rb\tc", expected: "a  b c"},
		{name: "empty string", input: "", expected: ""},
		{name: "multiple specials", input: "`*_|", expected: "\\`\\*\\_\\|"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := escapeMarkdownInline(tt.input)
			if result != tt.expected {
				t.Errorf("escapeMarkdownInline(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestEscapeMarkdownCodeBlock(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "normal code", input: "func main() {}", expected: "func main() {}"},
		{name: "triple backticks", input: "before ``` after", expected: "before ` ` ` after"},
		{name: "empty string", input: "", expected: ""},
		{name: "single backtick", input: "a `b` c", expected: "a `b` c"},
		{name: "multiple triple backticks", input: "```go\ncode\n```", expected: "` ` `go\ncode\n` ` `"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := escapeMarkdownCodeBlock(tt.input)
			if result != tt.expected {
				t.Errorf("escapeMarkdownCodeBlock(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestRiskPriority(t *testing.T) {
	tests := []struct {
		name     string
		risk     RiskLevel
		expected int
	}{
		{name: "critical", risk: RiskCritical, expected: 0},
		{name: "high", risk: RiskHigh, expected: 1},
		{name: "medium", risk: RiskMedium, expected: 2},
		{name: "low", risk: RiskLow, expected: 3},
		{name: "info", risk: RiskInfo, expected: 4},
		{name: "unknown", risk: RiskLevel("unknown"), expected: 5},
		{name: "empty", risk: RiskLevel(""), expected: 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := riskPriority(tt.risk)
			if result != tt.expected {
				t.Errorf("riskPriority(%q) = %d, want %d", tt.risk, result, tt.expected)
			}
		})
	}

	// Verify ordering: critical < high < medium < low < info
	if riskPriority(RiskCritical) >= riskPriority(RiskHigh) {
		t.Error("critical should have lower priority number than high")
	}
	if riskPriority(RiskHigh) >= riskPriority(RiskMedium) {
		t.Error("high should have lower priority number than medium")
	}
	if riskPriority(RiskMedium) >= riskPriority(RiskLow) {
		t.Error("medium should have lower priority number than low")
	}
}

func TestGetRecommendation(t *testing.T) {
	tests := []struct {
		name     string
		sinkType SinkType
		contains string
	}{
		{name: "exec sink", sinkType: SinkExec, contains: "command execution"},
		{name: "database sink", sinkType: SinkDatabase, contains: "parameterized queries"},
		{name: "response sink", sinkType: SinkResponse, contains: "EscapeString"},
		{name: "template sink", sinkType: SinkTemplate, contains: "auto-escapes"},
		{name: "redirect sink", sinkType: SinkRedirect, contains: "allow list"},
		{name: "file sink", sinkType: SinkFile, contains: "filepath.Clean"},
		{name: "log sink", sinkType: SinkLog, contains: "log injection"},
		{name: "unknown sink", sinkType: SinkType("unknown"), contains: "Review data flow"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flow := Flow{Sink: Sink{Type: tt.sinkType}}
			result := getRecommendation(flow)
			if !strings.Contains(result, tt.contains) {
				t.Errorf("getRecommendation() for sink %q = %q, want it to contain %q", tt.sinkType, result, tt.contains)
			}
		})
	}
}

func TestGenerateSecuritySummary(t *testing.T) {
	t.Run("nil map produces valid report", func(t *testing.T) {
		report := GenerateSecuritySummary(nil)
		if !strings.Contains(report, "# Security Data Flow Analysis") {
			t.Error("report should contain header")
		}
		if !strings.Contains(report, "Analysis Limits") {
			t.Error("report should include analysis limits section")
		}
		if !strings.Contains(report, "No critical, high-risk, or unchecked nil safety issues detected") {
			t.Error("report should indicate no issues for empty input")
		}
	})

	t.Run("empty map produces valid report", func(t *testing.T) {
		report := GenerateSecuritySummary(map[string]*FlowAnalysis{})
		if !strings.Contains(report, "# Security Data Flow Analysis") {
			t.Error("report should contain header")
		}
	})

	t.Run("map with nil value is skipped", func(t *testing.T) {
		report := GenerateSecuritySummary(map[string]*FlowAnalysis{
			"go": nil,
		})
		if !strings.Contains(report, "| Languages Analyzed | 0 |") {
			t.Error("nil analysis should not count as a language")
		}
	})

	t.Run("report with real findings", func(t *testing.T) {
		analyses := map[string]*FlowAnalysis{
			"go": {
				Language: "go",
				Statistics: Stats{
					TotalSources:     5,
					TotalSinks:       3,
					TotalFlows:       2,
					UnsanitizedFlows: 1,
					CriticalFlows:    1,
					HighRiskFlows:    0,
					NilRisks:         1,
				},
				Flows: []Flow{
					{
						Description: "SQL injection via user input",
						Source: Source{
							Type: SourceHTTPQuery,
							File: "handler.go",
							Line: 10,
						},
						Sink: Sink{
							Type:     SinkDatabase,
							File:     "repo.go",
							Line:     20,
							Function: "db.Query",
						},
						Risk: RiskCritical,
					},
				},
				NilSources: []NilSource{
					{
						File:      "service.go",
						Line:      15,
						Variable:  "result",
						Origin:    "db.Find",
						IsChecked: false,
						Risk:      RiskMedium,
					},
				},
			},
		}

		report := GenerateSecuritySummary(analyses)

		// Verify header
		if !strings.Contains(report, "# Security Data Flow Analysis") {
			t.Error("report should contain header")
		}

		// Verify executive summary
		if !strings.Contains(report, "| Total Sources | 5 |") {
			t.Error("report should contain total sources")
		}
		if !strings.Contains(report, "| Critical Risk Flows | 1 |") {
			t.Error("report should contain critical flows count")
		}

		// Verify critical section appears
		if !strings.Contains(report, "CRITICAL") {
			t.Error("report should contain CRITICAL section")
		}

		// Verify language breakdown
		if !strings.Contains(report, "### Go") {
			t.Error("report should contain language breakdown for Go")
		}

		// Verify nil safety table
		if !strings.Contains(report, "Nil/Null Safety Issues") {
			t.Error("report should contain nil safety section")
		}
		if !strings.Contains(report, "result") {
			t.Error("report should contain nil source variable name")
		}

		// Verify general recommendations
		if !strings.Contains(report, "General Recommendations") {
			t.Error("report should contain general recommendations")
		}
	})

	t.Run("multiple languages are sorted", func(t *testing.T) {
		analyses := map[string]*FlowAnalysis{
			"python": {Language: "python", Statistics: Stats{TotalSources: 1}},
			"go":     {Language: "go", Statistics: Stats{TotalSources: 2}},
		}

		report := GenerateSecuritySummary(analyses)

		goIdx := strings.Index(report, "### Go")
		pyIdx := strings.Index(report, "### Python")
		if goIdx == -1 || pyIdx == -1 {
			t.Fatal("report should contain both language breakdowns")
		}
		if goIdx > pyIdx {
			t.Error("Go should appear before Python (alphabetical order)")
		}
	})
}
