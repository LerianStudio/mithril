package context

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
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
		callerCount := len(f.Callers)
		if callerCount >= 5 {
			return "HIGH"
		}
		if callerCount >= 2 {
			return "MEDIUM"
		}
		return "LOW"
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

func sanitizeMarkdownText(value string) string {
	return markdownEscaper.Replace(value)
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

	return data
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
