package context

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"text/template"

	cgpkg "github.com/lerianstudio/mithril/internal/callgraph"
)

// Template definitions for each reviewer's context file.

const codeReviewerTemplate = `# Pre-Analysis Context: Code Quality

## Static Analysis Findings ({{.FindingCount}} issues)

{{if .Findings}}
| Severity | Tool | File | Line | Message |
|----------|------|------|------|---------|
{{- range .Findings}}
| {{.Severity}} | {{.Tool}} | {{.File}} | {{.Line}} | {{.Message}} |
{{- end}}
{{else}}
No static analysis findings.
{{end}}

## Semantic Changes

{{if .HasSemanticChanges}}
### Functions Modified ({{len .ModifiedFunctions}})
{{range .ModifiedFunctions}}
#### ` + "`{{.Package}}.{{.Name}}`" + `
**File:** ` + "`{{.File}}:{{.After.LineStart}}-{{.After.LineEnd}}`" + `
{{if .Changes}}**Changes:** {{join .Changes ", "}}{{end}}

{{if signatureChanged .}}
` + "```diff" + `
- {{.Before.Signature}}
+ {{.After.Signature}}
` + "```" + `
{{end}}
{{end}}

### Functions Added ({{len .AddedFunctions}})
{{range .AddedFunctions}}
- ` + "`{{.Package}}.{{.Name}}`" + ` at ` + "`{{.File}}:{{.LineStart}}`" + `
{{end}}

### Types Modified ({{len .ModifiedTypes}})
{{range .ModifiedTypes}}
#### ` + "`{{.Name}}`" + `
**File:** ` + "`{{.File}}`" + `

| Field | Before | After |
|-------|--------|-------|
{{- range fieldChanges .}}
| {{.Name}} | {{.Before}} | {{.After}} |
{{- end}}
{{end}}
{{else}}
No semantic changes detected.
{{end}}

## Focus Areas

Based on analysis, pay special attention to:
{{range $i, $area := .FocusAreas}}
{{inc $i}}. **{{$area.Title}}** - {{$area.Description}}
{{- end}}
{{if not .FocusAreas}}
No specific focus areas identified.
{{end}}
`

const securityReviewerTemplate = `# Pre-Analysis Context: Security

## Security Scanner Findings ({{.FindingCount}} issues)

{{if .Findings}}
| Severity | Tool | Rule | File | Line | Message |
|----------|------|------|------|------|---------|
{{- range .Findings}}
| {{.Severity}} | {{.Tool}} | {{.Rule}} | {{.File}} | {{.Line}} | {{.Message}} |
{{- end}}
{{else}}
No security scanner findings.
{{end}}

## Data Flow Analysis

{{if .HasDataFlowAnalysis}}
### High Risk Flows ({{len .HighRiskFlows}})
{{range .HighRiskFlows}}
#### {{.ID}}: {{.Source.Type}} -> {{.Sink.Type}}
**File:** ` + "`{{.Source.File}}:{{.Source.Line}}`" + `
**Risk:** {{.Risk}}
**Notes:** {{.Notes}}

**Source:** ` + "`{{.Source.Expression}}`" + `
**Sink:** ` + "`{{.Sink.Expression}}`" + `
**Sanitized:** {{if .Sanitized}}Yes{{else}}No{{end}}
{{end}}

### Medium Risk Flows ({{len .MediumRiskFlows}})
{{range .MediumRiskFlows}}
- {{.Source.Type}} -> {{.Sink.Type}} at ` + "`{{.Source.File}}:{{.Source.Line}}`" + ` ({{.Notes}})
{{- end}}
{{else}}
No data flow analysis available.
{{end}}

## Focus Areas

Based on analysis, pay special attention to:
{{range $i, $area := .FocusAreas}}
{{inc $i}}. **{{$area.Title}}** - {{$area.Description}}
{{- end}}
{{if not .FocusAreas}}
No specific focus areas identified.
{{end}}
`

const businessLogicReviewerTemplate = `# Pre-Analysis Context: Business Logic

## Impact Analysis

{{if .HasCallGraph}}
### High Impact Changes

{{if .CallGraphPartialResults}}
> Warning: call graph analysis is partial{{if .CallGraphTimeBudgetExceeded}} (time budget exceeded){{end}}.
{{end}}

{{if .CallGraphWarnings}}
**Call Graph Warnings:**
{{range .CallGraphWarnings}}
- {{.}}
{{end}}
{{end}}

{{range .HighImpactFunctions}}
#### ` + "`{{.Function}}`" + `
**File:** ` + "`{{.File}}`" + `
**Risk Level:** {{riskLevel .}} ({{len .Callers}} direct callers)

**Direct Callers (signature change affects these):**
{{range $i, $caller := .Callers}}
{{inc $i}}. ` + "`{{$caller.Function}}`" + ` - ` + "`{{$caller.File}}:{{$caller.Line}}`" + `
{{- end}}

**Callees (this function depends on):**
{{range $i, $callee := .Callees}}
{{inc $i}}. ` + "`{{$callee.Function}}`" + `
{{- end}}
{{end}}
{{else}}
No call graph analysis available.
{{end}}

## Semantic Changes

{{if .HasSemanticChanges}}
### Functions with Logic Changes
{{range $i, $f := .ModifiedFunctions}}
{{inc $i}}. **` + "`{{$f.Package}}.{{$f.Name}}`" + `** - {{join $f.Changes ", "}}
{{- end}}
{{else}}
No semantic changes detected.
{{end}}

## Focus Areas

Based on analysis, pay special attention to:
{{range $i, $area := .FocusAreas}}
{{inc $i}}. **{{$area.Title}}** - {{$area.Description}}
{{- end}}
{{if not .FocusAreas}}
No specific focus areas identified.
{{end}}
`

const testReviewerTemplate = `# Pre-Analysis Context: Testing

## Test Coverage for Modified Code

{{if .HasCallGraph}}
{{if .CallGraphPartialResults}}
> Warning: call graph analysis is partial{{if .CallGraphTimeBudgetExceeded}} (time budget exceeded){{end}}.
{{end}}

{{if .CallGraphWarnings}}
**Call Graph Warnings:**
{{range .CallGraphWarnings}}
- {{.}}
{{end}}
{{end}}

| Function | File | Tests | Status |
|----------|------|-------|--------|
{{- range .AllModifiedFunctionsGraph}}
| ` + "`{{.Function}}`" + ` | {{.File}} | {{len .TestCoverage}} tests | {{if eq (len .TestCoverage) 0}}No tests{{else}}{{len .TestCoverage}} tests{{end}} |
{{- end}}
{{else}}
No call graph analysis available for test coverage.
{{end}}

## Uncovered New Code

{{if .UncoveredFunctions}}
{{range .UncoveredFunctions}}
- ` + "`{{.Function}}`" + ` at ` + "`{{.File}}`" + ` - **No tests found**
{{- end}}
{{else}}
{{if eq (len .AllModifiedFunctionsGraph) 0}}
No callgraph data available.
{{else}}
All modified code has test coverage.
{{end}}
{{end}}

## Focus Areas

Based on analysis, pay special attention to:
{{range $i, $area := .FocusAreas}}
{{inc $i}}. **{{$area.Title}}** - {{$area.Description}}
{{- end}}
{{if not .FocusAreas}}
No specific focus areas identified.
{{end}}
`

const nilSafetyReviewerTemplate = `# Pre-Analysis Context: Nil Safety

## Nil Source Analysis

{{if .HasNilSources}}
| Variable | File | Line | Checked? | Risk |
|----------|------|------|----------|------|
{{- range .NilSources}}
| ` + "`{{.Variable}}`" + ` | {{.File}} | {{.Line}} | {{if .Checked}}Yes{{else}}No{{end}} | {{.Risk}} |
{{- end}}
{{else}}
No nil sources detected in changed code.
{{end}}

## High Risk Nil Sources

{{range .HighRiskNilSources}}
### ` + "`{{.Variable}}`" + ` at ` + "`{{.File}}:{{.Line}}`" + `
**Expression:** ` + "`{{.Expression}}`" + `
**Checked:** {{if .Checked}}Yes (line {{.CheckLine}}){{else}}No{{end}}
**Notes:** {{.Notes}}
{{end}}

## Focus Areas

Based on analysis, pay special attention to:
{{range $i, $area := .FocusAreas}}
{{inc $i}}. **{{$area.Title}}** - {{$area.Description}}
{{- end}}
{{if not .FocusAreas}}
No specific focus areas identified.
{{end}}
`

const consequencesReviewerTemplate = `# Pre-Analysis Context: Consequences

## API Surface Changes

{{if .HasConsequences}}
### Signature Changes ({{len .SignatureChanges}})
{{if .SignatureChanges}}
{{range .SignatureChanges}}
#### ` + "`{{.Package}}.{{.Name}}`" + `
**File:** ` + "`{{.File}}:{{.After.LineStart}}-{{.After.LineEnd}}`" + `

` + "```diff" + `
- {{.Before.Signature}}
+ {{.After.Signature}}
` + "```" + `
{{end}}
{{else}}
No signature changes detected.
{{end}}

### Type Shape Changes ({{len .TypeSurfaceChanges}})
{{if .TypeSurfaceChanges}}
{{range .TypeSurfaceChanges}}
#### ` + "`{{.Name}}`" + ` ({{.Kind}})
**File:** ` + "`{{.File}}`" + `

| Field | Before | After |
|-------|--------|-------|
{{- range fieldChanges .}}
| {{.Name}} | {{.Before}} | {{.After}} |
{{- end}}
{{end}}
{{else}}
No type shape changes.
{{end}}

### Dependency Changes
{{if or .ImportsAdded .ImportsRemoved}}
**Added imports ({{len .ImportsAdded}}):**
{{range .ImportsAdded}}
- ` + "`{{.Path}}{{.Module}}`" + ` in ` + "`{{.File}}`" + `
{{- end}}

**Removed imports ({{len .ImportsRemoved}}):**
{{range .ImportsRemoved}}
- ` + "`{{.Path}}{{.Module}}`" + ` in ` + "`{{.File}}`" + `
{{- end}}
{{else}}
No import changes.
{{end}}

## Caller Chain Impact

{{if .CallerImpactedFunctions}}
{{range .CallerImpactedFunctions}}
#### ` + "`{{.Function}}`" + `
**File:** ` + "`{{.File}}`" + `
**Risk Level:** {{riskLevel .}} ({{len .Callers}} direct callers)

**Direct callers (may break if behaviour or signature shifted):**
{{range $i, $caller := .Callers}}
{{inc $i}}. ` + "`{{$caller.Function}}`" + ` - ` + "`{{$caller.File}}:{{$caller.Line}}`" + `
{{- end}}

**Callees (implicit dependencies this function relies on):**
{{range $i, $callee := .Callees}}
{{inc $i}}. ` + "`{{$callee.Function}}`" + `
{{- end}}
{{end}}
{{else}}
No caller chain data available.
{{end}}

## Error Contract Shifts

### New error returns ({{len .ErrorReturnsAdded}})
{{if .ErrorReturnsAdded}}
{{range .ErrorReturnsAdded}}
- ` + "`{{.Function}}`" + ` at ` + "`{{.File}}:{{.Line}}`" + ` returns ` + "`{{.ErrorType}}`" + ` - {{.Message}}
{{- end}}
{{else}}
No new error returns.
{{end}}

### Removed error checks ({{len .ErrorChecksRemoved}})
{{if .ErrorChecksRemoved}}
{{range .ErrorChecksRemoved}}
- ` + "`{{.Function}}`" + ` at ` + "`{{.File}}:{{.Line}}`" + `
{{- end}}
{{else}}
No removed error checks.
{{end}}
{{else}}
No consequence signals detected from the change.
{{end}}

## Focus Areas

Based on analysis, pay special attention to:
{{range $i, $area := .FocusAreas}}
{{inc $i}}. **{{$area.Title}}** - {{$area.Description}}
{{- end}}
{{if not .FocusAreas}}
No specific focus areas identified.
{{end}}
`

const deadCodeReviewerTemplate = `# Pre-Analysis Context: Dead Code

## Deleted Symbols

{{if .HasDeadCodeSignals}}
### Deleted Functions ({{len .DeletedFunctions}})
{{if .DeletedFunctions}}
{{range .DeletedFunctions}}
- ` + "`{{.Package}}.{{.Name}}`" + ` at ` + "`{{.File}}:{{.LineStart}}`" + `
{{- end}}
{{else}}
No deleted functions.
{{end}}

### Deleted Types ({{len .DeletedTypes}})
{{if .DeletedTypes}}
{{range .DeletedTypes}}
- ` + "`{{.Type}}`" + `
{{- end}}
{{else}}
No deleted types.
{{end}}

### Removed Imports ({{len .RemovedImports}})
{{if .RemovedImports}}
{{range .RemovedImports}}
- ` + "`{{.Path}}{{.Module}}`" + ` in ` + "`{{.File}}`" + `
{{- end}}
{{else}}
No removed imports.
{{end}}

## Orphan Candidates

Functions modified in the change set whose reachable callers are missing.

{{if .OrphanFunctions}}
| Function | File | Callers | Callees |
|----------|------|---------|---------|
{{- range .OrphanFunctions}}
| ` + "`{{.Function}}`" + ` | {{.File}} | {{len .Callers}} | {{len .Callees}} |
{{- end}}
{{else}}
No orphan functions identified from the call graph.
{{end}}

## Zombie Tests

Tests that exercise functions which no longer have any production callers.

{{if .ZombieTests}}
{{range .ZombieTests}}
### ` + "`{{.Function}}`" + `
**File:** ` + "`{{.File}}`" + `
**Tests still referencing it:**
{{range $i, $t := .TestCoverage}}
{{inc $i}}. ` + "`{{$t.TestFunction}}`" + ` - ` + "`{{$t.File}}:{{$t.Line}}`" + `
{{- end}}
{{end}}
{{else}}
No zombie tests detected.
{{end}}
{{else}}
No dead-code signals detected. Dependency-graph walk is still recommended.
{{end}}

## Focus Areas

Based on analysis, pay special attention to:
{{range $i, $area := .FocusAreas}}
{{inc $i}}. **{{$area.Title}}** - {{$area.Description}}
{{- end}}
{{if not .FocusAreas}}
No specific focus areas identified.
{{end}}
`

// FocusArea represents a specific area requiring attention.
type FocusArea struct {
	Title       string
	Description string
}

// FieldChange represents a before/after field comparison.
type FieldChange struct {
	Name   string
	Before string
	After  string
}

// TemplateData holds data for template rendering.
type TemplateData struct {
	// Common fields
	FindingCount int
	Findings     []Finding
	FocusAreas   []FocusArea

	// Semantic changes (code-reviewer, business-logic-reviewer)
	HasSemanticChanges bool
	ModifiedFunctions  []FunctionDiff
	AddedFunctions     []FunctionInfo
	ModifiedTypes      []TypeDiff

	// Data flow (security-reviewer)
	HasDataFlowAnalysis bool
	HighRiskFlows       []DataFlow
	MediumRiskFlows     []DataFlow

	// Call graph (business-logic-reviewer, test-reviewer)
	HasCallGraph                bool
	CallGraphPartialResults     bool
	CallGraphTimeBudgetExceeded bool
	CallGraphWarnings           []string
	HighImpactFunctions         []FunctionCallGraph
	AllModifiedFunctionsGraph   []FunctionCallGraph // All modified functions with call graph data
	UncoveredFunctions          []FunctionCallGraph

	// Nil safety (nil-safety-reviewer)
	HasNilSources      bool
	NilSources         []NilSource
	HighRiskNilSources []NilSource

	// Consequences (consequences-reviewer): downstream effects of the change.
	HasConsequences         bool
	SignatureChanges        []FunctionDiff
	TypeSurfaceChanges      []TypeDiff
	ImportsAdded            []ImportInfo
	ImportsRemoved          []ImportInfo
	ErrorReturnsAdded       []ErrorReturn
	ErrorChecksRemoved      []ErrorCheck
	CallerImpactedFunctions []FunctionCallGraph

	// Dead code (dead-code-reviewer): orphans and zombies.
	HasDeadCodeSignals bool
	DeletedFunctions   []FunctionInfo
	DeletedTypes       []ReturnTypeInfo
	RemovedImports     []ImportInfo
	OrphanFunctions    []FunctionCallGraph
	ZombieTests        []FunctionCallGraph
}

// templateFuncs provides custom functions for templates.
var templateFuncs = template.FuncMap{
	"inc": func(i int) int {
		return i + 1
	},
	"join": func(items []string, sep string) string {
		if items == nil {
			return ""
		}
		return strings.Join(items, sep)
	},
	"signatureChanged": func(f FunctionDiff) bool {
		return f.Before.Signature != f.After.Signature
	},
	"fieldChanges": func(t TypeDiff) []FieldChange {
		var changes []FieldChange
		beforeMap := make(map[string]string)
		for _, f := range t.Before.Fields {
			beforeMap[f.Name] = f.Type
		}
		afterMap := make(map[string]string)
		for _, f := range t.After.Fields {
			afterMap[f.Name] = f.Type
		}

		// Find modified and added fields
		for _, f := range t.After.Fields {
			if before, ok := beforeMap[f.Name]; ok {
				if before != f.Type {
					changes = append(changes, FieldChange{
						Name:   f.Name,
						Before: before,
						After:  f.Type,
					})
				}
			} else {
				changes = append(changes, FieldChange{
					Name:   f.Name,
					Before: "-",
					After:  f.Type + " (added)",
				})
			}
		}

		// Find deleted fields
		for _, f := range t.Before.Fields {
			if _, ok := afterMap[f.Name]; !ok {
				changes = append(changes, FieldChange{
					Name:   f.Name,
					Before: f.Type,
					After:  "(deleted)",
				})
			}
		}

		return changes
	},
	"riskLevel": func(f FunctionCallGraph) string {
		return string(cgpkg.RiskLevelFromCallerCount(len(f.Callers)))
	},
}

var markdownEscaper = strings.NewReplacer(
	"`", "\\`",
	"*", "\\*",
	"_", "\\_",
	"[", "\\[",
	"]", "\\]",
	"(", "\\(",
	")", "\\)",
	"#", "\\#",
	"|", "\\|",
	"<", "&lt;",
	">", "&gt;",
	"\n", " ",
	"\r", " ",
	"\t", " ",
)

// secretRedactionPatterns matches common credential / secret shapes found in
// source code so they are not forwarded verbatim to LLM-bound context files.
// Each pair is (regex, replacement marker). These are intentionally coarse —
// false-positive redactions are safer than false negatives for this pipeline.
var secretRedactionPatterns = []struct {
	re     *regexp.Regexp
	marker string
}{
	// AWS access key IDs and secrets.
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), "[REDACTED:aws-access-key]"},
	{regexp.MustCompile(`\bASIA[0-9A-Z]{16}\b`), "[REDACTED:aws-temp-access-key]"},
	// GitHub tokens (ghp/ghs/gho/ghu/ghr).
	{regexp.MustCompile(`\bgh[pusor]_[A-Za-z0-9]{20,}\b`), "[REDACTED:github-token]"},
	// Slack tokens.
	{regexp.MustCompile(`\bxox[abpsr]-[A-Za-z0-9-]{10,}\b`), "[REDACTED:slack-token]"},
	// Stripe keys.
	{regexp.MustCompile(`\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b`), "[REDACTED:stripe-secret]"},
	{regexp.MustCompile(`\bpk_(?:live|test)_[A-Za-z0-9]{16,}\b`), "[REDACTED:stripe-publishable]"},
	// Google API key.
	{regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`), "[REDACTED:google-api-key]"},
	// PEM-encoded private keys (match the armor header; strip the whole line).
	{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`), "[REDACTED:private-key]"},
	// JWT-like tokens.
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`), "[REDACTED:jwt]"},
	// Database connection URIs with embedded credentials.
	{regexp.MustCompile(`\b(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|amqp|amqps)://[^:\s/]+:[^@\s]+@[^\s]+`), "[REDACTED:db-uri]"},
	// Generic high-entropy assignment on lines that contain a "password",
	// "secret", "api_key", or "token" attribute. Value must be >= 12 chars.
	{regexp.MustCompile(`(?i)(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*['"][^'"\s]{12,}['"]`), "[REDACTED:credential-assignment]"},
}

func redactSecrets(value string) string {
	for _, p := range secretRedactionPatterns {
		value = p.re.ReplaceAllString(value, p.marker)
	}
	return value
}

// promptInjectionPatterns detects crude natural-language prompt-injection
// attempts embedded in source code, commit messages, or diff content. These
// are heuristics, not a complete defense — they handle the "comment in source
// says ignore all previous instructions" class of attack that the pure
// markdown escaper misses.
var promptInjectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?`),
	regexp.MustCompile(`(?i)disregard\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?`),
	regexp.MustCompile(`(?i)forget\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?`),
	regexp.MustCompile(`(?i)you\s+are\s+now\s+(?:a|an)\s+`),
	regexp.MustCompile(`(?i)new\s+instructions?:\s*`),
	regexp.MustCompile(`(?i)system\s+prompt\s*[:=]`),
	regexp.MustCompile(`(?i)<\s*/?\s*(?:system|assistant|user)\s*>`),
}

func redactPromptInjection(value string) string {
	for _, p := range promptInjectionPatterns {
		value = p.ReplaceAllString(value, "[REDACTED:prompt-injection]")
	}
	return value
}

func sanitizeMarkdownText(value string) string {
	// Order matters: redact secrets first (so prompt-injection patterns can't
	// eat into a credential), then prompt-injection, then markdown-escape.
	return markdownEscaper.Replace(redactPromptInjection(redactSecrets(value)))
}

func sanitizeTemplateData(data *TemplateData) *TemplateData {
	if data == nil {
		return &TemplateData{}
	}

	for i := range data.Findings {
		data.Findings[i].Tool = sanitizeMarkdownText(data.Findings[i].Tool)
		data.Findings[i].Rule = sanitizeMarkdownText(data.Findings[i].Rule)
		data.Findings[i].Severity = sanitizeMarkdownText(data.Findings[i].Severity)
		data.Findings[i].File = sanitizeMarkdownText(data.Findings[i].File)
		data.Findings[i].Message = sanitizeMarkdownText(data.Findings[i].Message)
		data.Findings[i].Suggestion = sanitizeMarkdownText(data.Findings[i].Suggestion)
		data.Findings[i].Category = sanitizeMarkdownText(data.Findings[i].Category)
	}

	for i := range data.FocusAreas {
		data.FocusAreas[i].Title = sanitizeMarkdownText(data.FocusAreas[i].Title)
		data.FocusAreas[i].Description = sanitizeMarkdownText(data.FocusAreas[i].Description)
	}

	for i := range data.ModifiedFunctions {
		data.ModifiedFunctions[i].Name = sanitizeMarkdownText(data.ModifiedFunctions[i].Name)
		data.ModifiedFunctions[i].File = sanitizeMarkdownText(data.ModifiedFunctions[i].File)
		data.ModifiedFunctions[i].Package = sanitizeMarkdownText(data.ModifiedFunctions[i].Package)
		data.ModifiedFunctions[i].Module = sanitizeMarkdownText(data.ModifiedFunctions[i].Module)
		data.ModifiedFunctions[i].Receiver = sanitizeMarkdownText(data.ModifiedFunctions[i].Receiver)
		for j := range data.ModifiedFunctions[i].Changes {
			data.ModifiedFunctions[i].Changes[j] = sanitizeMarkdownText(data.ModifiedFunctions[i].Changes[j])
		}
		sanitizeFunctionInfo(&data.ModifiedFunctions[i].Before)
		sanitizeFunctionInfo(&data.ModifiedFunctions[i].After)
	}

	for i := range data.AddedFunctions {
		sanitizeFunctionInfo(&data.AddedFunctions[i])
	}

	for i := range data.ModifiedTypes {
		data.ModifiedTypes[i].Name = sanitizeMarkdownText(data.ModifiedTypes[i].Name)
		data.ModifiedTypes[i].Kind = sanitizeMarkdownText(data.ModifiedTypes[i].Kind)
		data.ModifiedTypes[i].File = sanitizeMarkdownText(data.ModifiedTypes[i].File)
		for j := range data.ModifiedTypes[i].Changes {
			data.ModifiedTypes[i].Changes[j] = sanitizeMarkdownText(data.ModifiedTypes[i].Changes[j])
		}
		for j := range data.ModifiedTypes[i].Before.Fields {
			sanitizeFieldInfo(&data.ModifiedTypes[i].Before.Fields[j])
		}
		for j := range data.ModifiedTypes[i].After.Fields {
			sanitizeFieldInfo(&data.ModifiedTypes[i].After.Fields[j])
		}
	}

	for i := range data.HighRiskFlows {
		sanitizeDataFlow(&data.HighRiskFlows[i])
	}
	for i := range data.MediumRiskFlows {
		sanitizeDataFlow(&data.MediumRiskFlows[i])
	}

	for i := range data.CallGraphWarnings {
		data.CallGraphWarnings[i] = sanitizeMarkdownText(data.CallGraphWarnings[i])
	}

	for i := range data.HighImpactFunctions {
		sanitizeFunctionCallGraph(&data.HighImpactFunctions[i])
	}
	for i := range data.AllModifiedFunctionsGraph {
		sanitizeFunctionCallGraph(&data.AllModifiedFunctionsGraph[i])
	}
	for i := range data.UncoveredFunctions {
		sanitizeFunctionCallGraph(&data.UncoveredFunctions[i])
	}

	for i := range data.NilSources {
		sanitizeNilSource(&data.NilSources[i])
	}
	for i := range data.HighRiskNilSources {
		sanitizeNilSource(&data.HighRiskNilSources[i])
	}

	for i := range data.SignatureChanges {
		data.SignatureChanges[i].Name = sanitizeMarkdownText(data.SignatureChanges[i].Name)
		data.SignatureChanges[i].File = sanitizeMarkdownText(data.SignatureChanges[i].File)
		data.SignatureChanges[i].Package = sanitizeMarkdownText(data.SignatureChanges[i].Package)
		data.SignatureChanges[i].Module = sanitizeMarkdownText(data.SignatureChanges[i].Module)
		data.SignatureChanges[i].Receiver = sanitizeMarkdownText(data.SignatureChanges[i].Receiver)
		sanitizeFunctionInfo(&data.SignatureChanges[i].Before)
		sanitizeFunctionInfo(&data.SignatureChanges[i].After)
	}
	for i := range data.TypeSurfaceChanges {
		data.TypeSurfaceChanges[i].Name = sanitizeMarkdownText(data.TypeSurfaceChanges[i].Name)
		data.TypeSurfaceChanges[i].Kind = sanitizeMarkdownText(data.TypeSurfaceChanges[i].Kind)
		data.TypeSurfaceChanges[i].File = sanitizeMarkdownText(data.TypeSurfaceChanges[i].File)
		for j := range data.TypeSurfaceChanges[i].Before.Fields {
			sanitizeFieldInfo(&data.TypeSurfaceChanges[i].Before.Fields[j])
		}
		for j := range data.TypeSurfaceChanges[i].After.Fields {
			sanitizeFieldInfo(&data.TypeSurfaceChanges[i].After.Fields[j])
		}
	}
	sanitizeImports(data.ImportsAdded)
	sanitizeImports(data.ImportsRemoved)
	sanitizeImports(data.RemovedImports)
	for i := range data.ErrorReturnsAdded {
		data.ErrorReturnsAdded[i].Function = sanitizeMarkdownText(data.ErrorReturnsAdded[i].Function)
		data.ErrorReturnsAdded[i].File = sanitizeMarkdownText(data.ErrorReturnsAdded[i].File)
		data.ErrorReturnsAdded[i].ErrorType = sanitizeMarkdownText(data.ErrorReturnsAdded[i].ErrorType)
		data.ErrorReturnsAdded[i].Message = sanitizeMarkdownText(data.ErrorReturnsAdded[i].Message)
	}
	for i := range data.ErrorChecksRemoved {
		data.ErrorChecksRemoved[i].Function = sanitizeMarkdownText(data.ErrorChecksRemoved[i].Function)
		data.ErrorChecksRemoved[i].File = sanitizeMarkdownText(data.ErrorChecksRemoved[i].File)
	}
	for i := range data.CallerImpactedFunctions {
		sanitizeFunctionCallGraph(&data.CallerImpactedFunctions[i])
	}
	for i := range data.DeletedFunctions {
		sanitizeFunctionInfo(&data.DeletedFunctions[i])
	}
	for i := range data.DeletedTypes {
		data.DeletedTypes[i].Type = sanitizeMarkdownText(data.DeletedTypes[i].Type)
	}
	for i := range data.OrphanFunctions {
		sanitizeFunctionCallGraph(&data.OrphanFunctions[i])
	}
	for i := range data.ZombieTests {
		sanitizeFunctionCallGraph(&data.ZombieTests[i])
	}

	return data
}

func sanitizeImports(imports []ImportInfo) {
	for i := range imports {
		imports[i].File = sanitizeMarkdownText(imports[i].File)
		imports[i].Path = sanitizeMarkdownText(imports[i].Path)
		imports[i].Module = sanitizeMarkdownText(imports[i].Module)
		for j := range imports[i].Names {
			imports[i].Names[j] = sanitizeMarkdownText(imports[i].Names[j])
		}
	}
}

func sanitizeFunctionInfo(info *FunctionInfo) {
	if info == nil {
		return
	}
	info.Name = sanitizeMarkdownText(info.Name)
	info.Signature = sanitizeMarkdownText(info.Signature)
	info.File = sanitizeMarkdownText(info.File)
	info.Package = sanitizeMarkdownText(info.Package)
	for i := range info.Params {
		info.Params[i].Name = sanitizeMarkdownText(info.Params[i].Name)
		info.Params[i].Type = sanitizeMarkdownText(info.Params[i].Type)
		info.Params[i].Default = sanitizeMarkdownText(info.Params[i].Default)
	}
	for i := range info.Returns {
		info.Returns[i].Type = sanitizeMarkdownText(info.Returns[i].Type)
	}
}

func sanitizeFieldInfo(field *FieldInfo) {
	if field == nil {
		return
	}
	field.Name = sanitizeMarkdownText(field.Name)
	field.Type = sanitizeMarkdownText(field.Type)
	field.Tags = sanitizeMarkdownText(field.Tags)
}

func sanitizeDataFlow(flow *DataFlow) {
	if flow == nil {
		return
	}
	flow.ID = sanitizeMarkdownText(flow.ID)
	flow.Risk = sanitizeMarkdownText(flow.Risk)
	flow.Notes = sanitizeMarkdownText(flow.Notes)

	flow.Source.Type = sanitizeMarkdownText(flow.Source.Type)
	flow.Source.Subtype = sanitizeMarkdownText(flow.Source.Subtype)
	flow.Source.Framework = sanitizeMarkdownText(flow.Source.Framework)
	flow.Source.Variable = sanitizeMarkdownText(flow.Source.Variable)
	flow.Source.File = sanitizeMarkdownText(flow.Source.File)
	flow.Source.Expression = sanitizeMarkdownText(flow.Source.Expression)

	for i := range flow.Path {
		flow.Path[i].File = sanitizeMarkdownText(flow.Path[i].File)
		flow.Path[i].Expression = sanitizeMarkdownText(flow.Path[i].Expression)
		flow.Path[i].Operation = sanitizeMarkdownText(flow.Path[i].Operation)
		flow.Path[i].SanitizerType = sanitizeMarkdownText(flow.Path[i].SanitizerType)
	}

	flow.Sink.Type = sanitizeMarkdownText(flow.Sink.Type)
	flow.Sink.Subtype = sanitizeMarkdownText(flow.Sink.Subtype)
	flow.Sink.File = sanitizeMarkdownText(flow.Sink.File)
	flow.Sink.Expression = sanitizeMarkdownText(flow.Sink.Expression)
}

func sanitizeFunctionCallGraph(graph *FunctionCallGraph) {
	if graph == nil {
		return
	}
	graph.Function = sanitizeMarkdownText(graph.Function)
	graph.File = sanitizeMarkdownText(graph.File)
	for i := range graph.Callers {
		graph.Callers[i].Function = sanitizeMarkdownText(graph.Callers[i].Function)
		graph.Callers[i].File = sanitizeMarkdownText(graph.Callers[i].File)
		graph.Callers[i].CallSite = sanitizeMarkdownText(graph.Callers[i].CallSite)
	}
	for i := range graph.Callees {
		graph.Callees[i].Function = sanitizeMarkdownText(graph.Callees[i].Function)
		graph.Callees[i].File = sanitizeMarkdownText(graph.Callees[i].File)
		graph.Callees[i].CallSite = sanitizeMarkdownText(graph.Callees[i].CallSite)
	}
	for i := range graph.TestCoverage {
		graph.TestCoverage[i].TestFunction = sanitizeMarkdownText(graph.TestCoverage[i].TestFunction)
		graph.TestCoverage[i].File = sanitizeMarkdownText(graph.TestCoverage[i].File)
	}
}

func sanitizeNilSource(source *NilSource) {
	if source == nil {
		return
	}
	source.Variable = sanitizeMarkdownText(source.Variable)
	source.File = sanitizeMarkdownText(source.File)
	source.Expression = sanitizeMarkdownText(source.Expression)
	source.CheckExpression = sanitizeMarkdownText(source.CheckExpression)
	source.Risk = sanitizeMarkdownText(source.Risk)
	source.Notes = sanitizeMarkdownText(source.Notes)
}

// RenderTemplate renders a template with the given data.
func RenderTemplate(templateStr string, data *TemplateData) (string, error) {
	tmpl, err := template.New("context").Funcs(templateFuncs).Parse(templateStr)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, sanitizeTemplateData(data)); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

var reviewerTemplates = map[string]string{
	"code-reviewer":           codeReviewerTemplate,
	"security-reviewer":       securityReviewerTemplate,
	"business-logic-reviewer": businessLogicReviewerTemplate,
	"test-reviewer":           testReviewerTemplate,
	"nil-safety-reviewer":     nilSafetyReviewerTemplate,
	"consequences-reviewer":   consequencesReviewerTemplate,
	"dead-code-reviewer":      deadCodeReviewerTemplate,
}

func hasTemplateForReviewer(reviewer string) bool {
	_, ok := reviewerTemplates[reviewer]
	return ok
}

// GetTemplateForReviewer returns the template string for a specific reviewer.
func GetTemplateForReviewer(reviewer string) (string, error) {
	if templateStr, ok := reviewerTemplates[reviewer]; ok {
		return templateStr, nil
	}
	return "", fmt.Errorf("unknown reviewer: %s", reviewer)
}
