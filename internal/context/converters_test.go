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
