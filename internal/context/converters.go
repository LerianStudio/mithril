package context

import (
	"encoding/json"
	"fmt"
	"strings"

	astpkg "github.com/lerianstudio/mithril/internal/ast"
	dataflowpkg "github.com/lerianstudio/mithril/internal/dataflow"
)

func parseASTData(data []byte) (*ASTData, error) {
	var direct ASTData
	if err := json.Unmarshal(data, &direct); err == nil {
		normalizeASTData(&direct)
		return &direct, nil
	}

	var diffs []astpkg.SemanticDiff
	if err := json.Unmarshal(data, &diffs); err != nil {
		return nil, fmt.Errorf("failed to parse AST output in supported formats: %w", err)
	}

	converted := convertSemanticDiffsToASTData(diffs)
	normalizeASTData(converted)
	return converted, nil
}

func normalizeASTData(astData *ASTData) {
	if astData == nil {
		return
	}
	if astData.Functions.Modified == nil {
		astData.Functions.Modified = []FunctionDiff{}
	}
	if astData.Functions.Added == nil {
		astData.Functions.Added = []FunctionInfo{}
	}
	if astData.Functions.Deleted == nil {
		astData.Functions.Deleted = []FunctionInfo{}
	}
	if astData.Types.Modified == nil {
		astData.Types.Modified = []TypeDiff{}
	}
	if astData.Types.Added == nil {
		astData.Types.Added = []ReturnTypeInfo{}
	}
	if astData.Types.Deleted == nil {
		astData.Types.Deleted = []ReturnTypeInfo{}
	}
	if astData.Imports.Added == nil {
		astData.Imports.Added = []ImportInfo{}
	}
	if astData.Imports.Removed == nil {
		astData.Imports.Removed = []ImportInfo{}
	}
}

func convertSemanticDiffsToASTData(diffs []astpkg.SemanticDiff) *ASTData {
	result := &ASTData{
		Functions: FunctionChanges{Modified: []FunctionDiff{}, Added: []FunctionInfo{}, Deleted: []FunctionInfo{}},
		Types:     TypeChanges{Modified: []TypeDiff{}, Added: []ReturnTypeInfo{}, Deleted: []ReturnTypeInfo{}},
		Imports:   ImportChanges{Added: []ImportInfo{}, Removed: []ImportInfo{}},
	}

	for _, diff := range diffs {
		for _, fn := range diff.Functions {
			switch fn.ChangeType {
			case astpkg.ChangeModified:
				if fn.Before == nil && fn.After == nil {
					continue
				}
				before, beforeOK := convertFuncSig(diff.FilePath, fn.Name, fn.Before)
				after, afterOK := convertFuncSig(diff.FilePath, fn.Name, fn.After)
				if !beforeOK && !afterOK {
					continue
				}
				changes := []string{}
				if fn.BodyDiff != "" {
					changes = append(changes, fn.BodyDiff)
				}
				if beforeOK && afterOK && before.Signature != after.Signature {
					changes = append(changes, "signature_changed")
				}
				result.Functions.Modified = append(result.Functions.Modified, FunctionDiff{
					Name:     fn.Name,
					File:     diff.FilePath,
					Receiver: firstNonEmpty(receiverFromSig(fn.After), receiverFromSig(fn.Before)),
					Before:   before,
					After:    after,
					Changes:  changes,
				})
			case astpkg.ChangeAdded:
				if info, ok := convertFuncSig(diff.FilePath, fn.Name, fn.After); ok {
					result.Functions.Added = append(result.Functions.Added, info)
				}
			case astpkg.ChangeRemoved:
				if info, ok := convertFuncSig(diff.FilePath, fn.Name, fn.Before); ok {
					result.Functions.Deleted = append(result.Functions.Deleted, info)
				}
			}
		}

		for _, typeDiff := range diff.Types {
			switch typeDiff.ChangeType {
			case astpkg.ChangeModified:
				beforeFields, afterFields, changes := convertTypeFields(typeDiff.Fields)
				result.Types.Modified = append(result.Types.Modified, TypeDiff{
					Name: typeDiff.Name,
					Kind: typeDiff.Kind,
					File: diff.FilePath,
					Before: FieldsData{
						Fields: beforeFields,
					},
					After: FieldsData{
						Fields: afterFields,
					},
					Changes: changes,
				})
			case astpkg.ChangeAdded:
				result.Types.Added = append(result.Types.Added, ReturnTypeInfo{Type: typeDiff.Name})
			case astpkg.ChangeRemoved:
				result.Types.Deleted = append(result.Types.Deleted, ReturnTypeInfo{Type: typeDiff.Name})
			}
		}

		for _, imp := range diff.Imports {
			entry := ImportInfo{File: diff.FilePath, Path: imp.Path}
			switch imp.ChangeType {
			case astpkg.ChangeAdded:
				result.Imports.Added = append(result.Imports.Added, entry)
			case astpkg.ChangeRemoved:
				result.Imports.Removed = append(result.Imports.Removed, entry)
			}
		}
	}

	return result
}

// convertFuncSig converts a producer FuncSig to a consumer FunctionInfo.
// Returns ok=false when sig is nil so callers can skip absent sides instead
// of synthesizing misleading `func NAME()` placeholders.
func convertFuncSig(filePath, name string, sig *astpkg.FuncSig) (FunctionInfo, bool) {
	if sig == nil {
		return FunctionInfo{}, false
	}

	params := make([]ParamInfo, 0, len(sig.Params))
	for _, p := range sig.Params {
		params = append(params, ParamInfo{Name: p.Name, Type: p.Type})
	}

	returns := make([]ReturnTypeInfo, 0, len(sig.Returns))
	for _, ret := range sig.Returns {
		returns = append(returns, ReturnTypeInfo{Type: ret})
	}

	return FunctionInfo{
		Name:      name,
		File:      filePath,
		Signature: buildFunctionSignature(name, sig),
		LineStart: sig.StartLine,
		LineEnd:   sig.EndLine,
		Params:    params,
		Returns:   returns,
	}, true
}

func buildFunctionSignature(name string, sig *astpkg.FuncSig) string {
	if sig == nil {
		return fmt.Sprintf("func %s()", name)
	}

	params := make([]string, 0, len(sig.Params))
	for _, p := range sig.Params {
		if p.Name == "" {
			params = append(params, p.Type)
			continue
		}
		params = append(params, fmt.Sprintf("%s %s", p.Name, p.Type))
	}

	returns := strings.Join(sig.Returns, ", ")
	receiver := receiverFromSig(sig)

	prefix := "func "
	if receiver != "" {
		prefix = fmt.Sprintf("func (%s) ", receiver)
	}

	signature := fmt.Sprintf("%s%s(%s)", prefix, name, strings.Join(params, ", "))
	if returns == "" {
		return signature
	}
	if len(sig.Returns) == 1 {
		return signature + " " + returns
	}
	return signature + " (" + returns + ")"
}

func receiverFromSig(sig *astpkg.FuncSig) string {
	if sig == nil {
		return ""
	}
	return strings.TrimSpace(sig.Receiver)
}

func convertTypeFields(fields []astpkg.FieldDiff) ([]FieldInfo, []FieldInfo, []string) {
	before := make([]FieldInfo, 0)
	after := make([]FieldInfo, 0)
	changes := make([]string, 0, len(fields))

	for _, field := range fields {
		changes = append(changes, fmt.Sprintf("%s:%s", field.Name, field.ChangeType))
		switch field.ChangeType {
		case astpkg.ChangeAdded:
			after = append(after, FieldInfo{Name: field.Name, Type: field.NewType})
		case astpkg.ChangeRemoved:
			before = append(before, FieldInfo{Name: field.Name, Type: field.OldType})
		case astpkg.ChangeModified:
			before = append(before, FieldInfo{Name: field.Name, Type: field.OldType})
			after = append(after, FieldInfo{Name: field.Name, Type: field.NewType})
		}
	}

	return before, after, changes
}

// parseDataFlowData parses raw data-flow JSON into the consumer DataFlowData
// shape. The producer (internal/dataflow.FlowAnalysis) is the single
// canonical input format; we always route through the converter so the
// FlowSummary is computed from the producer's Statistics and Flow list
// rather than direct-unmarshalled (H28/#4). Previously a try-direct-first
// branch existed but it never succeeded on real producer payloads because
// producer `path` is []string while consumer `Path` is []FlowStep — the
// direct path would only match a hand-crafted consumer-native sample, and
// keeping it around only created drift-risk for the FlowSummary fields.
func parseDataFlowData(data []byte) (*DataFlowData, error) {
	var producer dataflowpkg.FlowAnalysis
	if err := json.Unmarshal(data, &producer); err != nil {
		return nil, fmt.Errorf("failed to parse data flow output: %w", err)
	}

	converted := convertFlowAnalysisToDataFlowData(&producer)
	normalizeDataFlowData(converted)
	return converted, nil
}

func normalizeDataFlowData(flowData *DataFlowData) {
	if flowData == nil {
		return
	}
	if flowData.Flows == nil {
		flowData.Flows = []DataFlow{}
	}
	if flowData.NilSources == nil {
		flowData.NilSources = []NilSource{}
	}
}

func convertFlowAnalysisToDataFlowData(producer *dataflowpkg.FlowAnalysis) *DataFlowData {
	result := &DataFlowData{
		Flows:      make([]DataFlow, 0, len(producer.Flows)),
		NilSources: make([]NilSource, 0, len(producer.NilSources)),
	}

	for _, flow := range producer.Flows {
		path := make([]FlowStep, 0, len(flow.Path))
		for i, step := range flow.Path {
			path = append(path, FlowStep{
				Step:       i + 1,
				Expression: step,
				Operation:  "propagate",
			})
		}

		result.Flows = append(result.Flows, DataFlow{
			ID: flow.ID,
			Source: FlowSource{
				Type:       string(flow.Source.Type),
				Variable:   flow.Source.Variable,
				File:       flow.Source.File,
				Line:       flow.Source.Line,
				Expression: firstNonEmpty(flow.Source.Context, flow.Source.Pattern, flow.Source.Variable),
			},
			Path: path,
			Sink: FlowSink{
				Type:       string(flow.Sink.Type),
				Subtype:    flow.Sink.Function,
				File:       flow.Sink.File,
				Line:       flow.Sink.Line,
				Expression: firstNonEmpty(flow.Sink.Context, flow.Sink.Function, flow.Sink.Pattern),
			},
			Sanitized: flow.Sanitized,
			Risk:      string(flow.Risk),
			Notes:     flow.Description,
		})
	}

	for _, nilSource := range producer.NilSources {
		result.NilSources = append(result.NilSources, NilSource{
			Variable:   nilSource.Variable,
			File:       nilSource.File,
			Line:       nilSource.Line,
			Expression: firstNonEmpty(nilSource.Variable, nilSource.Origin),
			Checked:    nilSource.IsChecked,
			CheckLine:  nilSource.CheckLine,
			Risk:       string(nilSource.Risk),
			Notes:      nilSource.Origin,
		})
	}

	result.Summary = FlowSummary{
		TotalFlows:       firstNonZero(producer.Statistics.TotalFlows, len(result.Flows)),
		UnsanitizedFlows: producer.Statistics.UnsanitizedFlows,
		NilRisks:         firstNonZero(producer.Statistics.NilRisks, len(result.NilSources)),
	}

	// Count sanitized/unsanitized positively from the flow list so the two
	// never go out of sync with TotalFlows due to stats drift or subtraction.
	sanitized, unsanitized := 0, 0
	for _, flow := range result.Flows {
		if flow.Sanitized {
			sanitized++
		} else {
			unsanitized++
		}
	}
	if result.Summary.UnsanitizedFlows == 0 {
		result.Summary.UnsanitizedFlows = unsanitized
	}
	result.Summary.SanitizedFlows = sanitized

	computedHighRisk := 0
	for _, flow := range result.Flows {
		switch flow.Risk {
		case string(dataflowpkg.RiskCritical), string(dataflowpkg.RiskHigh):
			result.Summary.HighRisk++
			computedHighRisk++
		case string(dataflowpkg.RiskMedium):
			result.Summary.MediumRisk++
		case string(dataflowpkg.RiskLow):
			result.Summary.LowRisk++
		default:
			result.Summary.NoneRisks++
		}
	}

	statsHighRisk := producer.Statistics.HighRiskFlows + producer.Statistics.CriticalFlows
	if computedHighRisk == 0 && statsHighRisk > 0 {
		result.Summary.HighRisk = statsHighRisk
	} else if statsHighRisk > result.Summary.HighRisk {
		result.Summary.HighRisk = statsHighRisk
	}

	return result
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func firstNonZero(primary, fallback int) int {
	if primary > 0 {
		return primary
	}
	return fallback
}
