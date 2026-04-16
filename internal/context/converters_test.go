package context

import (
	"encoding/json"
	"testing"

	astpkg "github.com/lerianstudio/mithril/internal/ast"
	dataflowpkg "github.com/lerianstudio/mithril/internal/dataflow"
	"github.com/stretchr/testify/require"
)

func TestParseASTData_ConvertsSemanticDiffArray(t *testing.T) {
	raw, err := json.Marshal([]astpkg.SemanticDiff{
		{
			Language: "go",
			FilePath: "internal/service/user.go",
			Functions: []astpkg.FunctionDiff{
				{
					Name:       "CreateUser",
					ChangeType: astpkg.ChangeModified,
					Before: &astpkg.FuncSig{
						Params:    []astpkg.Param{{Name: "ctx", Type: "context.Context"}},
						Returns:   []string{"error"},
						StartLine: 10,
						EndLine:   20,
					},
					After: &astpkg.FuncSig{
						Params:    []astpkg.Param{{Name: "ctx", Type: "context.Context"}, {Name: "user", Type: "User"}},
						Returns:   []string{"error"},
						StartLine: 10,
						EndLine:   24,
					},
				},
				{
					Name:       "NotifyUser",
					ChangeType: astpkg.ChangeAdded,
					After: &astpkg.FuncSig{
						Params:    []astpkg.Param{{Name: "email", Type: "string"}},
						Returns:   []string{"error"},
						StartLine: 30,
						EndLine:   38,
					},
				},
			},
			Types: []astpkg.TypeDiff{{Name: "User", Kind: "struct", ChangeType: astpkg.ChangeAdded}},
			Imports: []astpkg.ImportDiff{
				{Path: "fmt", ChangeType: astpkg.ChangeRemoved},
				{Path: "log", ChangeType: astpkg.ChangeAdded},
			},
		},
	})
	require.NoError(t, err)

	parsed, err := parseASTData(raw)
	require.NoError(t, err)
	require.Len(t, parsed.Functions.Modified, 1)
	require.Len(t, parsed.Functions.Added, 1)
	require.Len(t, parsed.Types.Added, 1)
	require.Len(t, parsed.Imports.Added, 1)
	require.Len(t, parsed.Imports.Removed, 1)

	require.Equal(t, "CreateUser", parsed.Functions.Modified[0].Name)
	require.Equal(t, "NotifyUser", parsed.Functions.Added[0].Name)
	require.Contains(t, parsed.Functions.Modified[0].After.Signature, "CreateUser")
}

func TestParseDataFlowData_ConvertsFlowAnalysis(t *testing.T) {
	raw, err := json.Marshal(dataflowpkg.FlowAnalysis{
		Language: "go",
		Flows: []dataflowpkg.Flow{
			{
				ID: "flow-1",
				Source: dataflowpkg.Source{
					Type:     dataflowpkg.SourceHTTPQuery,
					File:     "handler.go",
					Line:     12,
					Variable: "userID",
					Pattern:  "request.URL.Query()",
				},
				Sink: dataflowpkg.Sink{
					Type:     dataflowpkg.SinkDatabase,
					File:     "repo.go",
					Line:     44,
					Function: "db.Exec",
					Pattern:  "Exec()",
				},
				Path:        []string{"handler.go:12 userID", "repo.go:44 db.Exec"},
				Sanitized:   false,
				Risk:        dataflowpkg.RiskCritical,
				Description: "unsanitized query to database",
			},
		},
		NilSources: []dataflowpkg.NilSource{{
			Variable:  "user",
			File:      "service.go",
			Line:      30,
			Origin:    "database_query",
			IsChecked: false,
			Risk:      dataflowpkg.RiskHigh,
		}},
		Statistics: dataflowpkg.Stats{TotalFlows: 1, UnsanitizedFlows: 1, CriticalFlows: 1, NilRisks: 1},
	})
	require.NoError(t, err)

	parsed, err := parseDataFlowData(raw)
	require.NoError(t, err)
	require.Len(t, parsed.Flows, 1)
	require.Len(t, parsed.NilSources, 1)
	require.Equal(t, 1, parsed.Summary.TotalFlows)
	require.Equal(t, 1, parsed.Summary.UnsanitizedFlows)
	require.Equal(t, 1, parsed.Summary.HighRisk)
	require.Equal(t, 1, parsed.Summary.NilRisks)
	require.Equal(t, "request.URL.Query()", parsed.Flows[0].Source.Expression)
	require.Equal(t, "db.Exec", parsed.Flows[0].Sink.Expression)
	require.Len(t, parsed.Flows[0].Path, 2)
}

// H22 regression: when a producer function diff has a nil Before or After
// signature, convertSemanticDiffsToASTData must NOT synthesize a fake
// `func NAME()` placeholder. Previously the converter filled in a bare
// signature string which the downstream reviewer would treat as authoritative.
func TestConvertSemanticDiffsToASTData_NoFakeSignatures(t *testing.T) {
	diffs := []astpkg.SemanticDiff{
		{
			Language: "go",
			FilePath: "internal/svc/a.go",
			Functions: []astpkg.FunctionDiff{
				{Name: "OnlyBeforeMissing", ChangeType: astpkg.ChangeModified,
					Before: nil,
					After:  &astpkg.FuncSig{Params: []astpkg.Param{{Name: "x", Type: "int"}}, StartLine: 5, EndLine: 8}},
				{Name: "OnlyAfterMissing", ChangeType: astpkg.ChangeModified,
					Before: &astpkg.FuncSig{Params: []astpkg.Param{{Name: "x", Type: "int"}}, StartLine: 5, EndLine: 8},
					After:  nil},
				{Name: "BothMissing", ChangeType: astpkg.ChangeModified,
					Before: nil, After: nil},
				{Name: "AddedButNil", ChangeType: astpkg.ChangeAdded, After: nil},
				{Name: "RemovedButNil", ChangeType: astpkg.ChangeRemoved, Before: nil},
			},
		},
	}

	result := convertSemanticDiffsToASTData(diffs)

	// BothMissing, AddedButNil, RemovedButNil must be dropped.
	for _, fn := range result.Functions.Modified {
		if fn.Name == "BothMissing" {
			t.Errorf("BothMissing should not appear in Modified, got %+v", fn)
		}
		if fn.Before.Signature == "func "+fn.Name+"()" && fn.Before.LineStart == 0 {
			t.Errorf("Modified %q Before has synthesized placeholder signature", fn.Name)
		}
		if fn.After.Signature == "func "+fn.Name+"()" && fn.After.LineStart == 0 {
			t.Errorf("Modified %q After has synthesized placeholder signature", fn.Name)
		}
	}
	for _, fn := range result.Functions.Added {
		if fn.Name == "AddedButNil" {
			t.Errorf("AddedButNil should be dropped (nil After), got %+v", fn)
		}
	}
	for _, fn := range result.Functions.Deleted {
		if fn.Name == "RemovedButNil" {
			t.Errorf("RemovedButNil should be dropped (nil Before), got %+v", fn)
		}
	}

	// OnlyBeforeMissing: After populated, Before zero-valued (not a fake placeholder).
	var onlyBeforeMissing *FunctionDiff
	for i, fn := range result.Functions.Modified {
		if fn.Name == "OnlyBeforeMissing" {
			onlyBeforeMissing = &result.Functions.Modified[i]
			break
		}
	}
	require.NotNil(t, onlyBeforeMissing, "OnlyBeforeMissing should be present with populated After")
	require.NotEmpty(t, onlyBeforeMissing.After.Signature)
	require.Empty(t, onlyBeforeMissing.Before.Signature, "Before side must be zero value, not a placeholder")
}

// H27 regression: SanitizedFlows is counted positively from the flow list,
// never derived by subtraction that could underflow or disagree with totals.
func TestConvertFlowAnalysisToDataFlowData_SanitizedCountedPositively(t *testing.T) {
	producer := &dataflowpkg.FlowAnalysis{
		Language: "go",
		Flows: []dataflowpkg.Flow{
			{ID: "f1", Sanitized: true, Risk: dataflowpkg.RiskLow},
			{ID: "f2", Sanitized: false, Risk: dataflowpkg.RiskHigh},
			{ID: "f3", Sanitized: true, Risk: dataflowpkg.RiskMedium},
		},
		// Intentionally inflate TotalFlows beyond len(Flows) to prove we don't
		// subtract into negatives or mismatch the actual list.
		Statistics: dataflowpkg.Stats{TotalFlows: 10, UnsanitizedFlows: 0},
	}

	result := convertFlowAnalysisToDataFlowData(producer)

	require.Equal(t, 2, result.Summary.SanitizedFlows, "should count sanitized positively")
	require.Equal(t, 1, result.Summary.UnsanitizedFlows, "should count unsanitized positively when stats say 0")
	require.GreaterOrEqual(t, result.Summary.SanitizedFlows, 0)
}
