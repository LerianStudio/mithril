package context

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	astpkg "github.com/lerianstudio/mithril/internal/ast"
)

// The tests in this file lock the wire format between Mithril's producer
// binaries (run-all, scope-detector, ast-extractor, call-graph, data-flow)
// and the context compiler that consumes their output. They exercise the
// consumer-side parsers (parseASTData, parseDataFlowData, json.Unmarshal on
// CallGraphData / StaticAnalysisData / ScopeData) against hand-crafted JSON
// samples representing the exact shapes the producers write today.
//
// A test here fails the moment either side drifts from the other — catching
// bugs like the C21/FlowSummary "summary" vs "statistics" mismatch before
// they silently zero out fields in production.

// readGolden loads a golden JSON file from internal/context/testdata.
func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("testdata", name)
	data, err := os.ReadFile(path) // #nosec G304 — path composed from literal testdata dir
	if err != nil {
		t.Fatalf("failed to read golden %s: %v", name, err)
	}
	return data
}

// TestGolden_MixedAST exercises the array-of-SemanticDiff wire format that
// run-all writes to `mixed-ast.json`. The compiler's parseASTData falls
// through to the `[]astpkg.SemanticDiff` branch and converts to ASTData.
// The test asserts the fall-through path actually populates the consumer
// structures instead of silently yielding an empty diff.
func TestGolden_MixedAST_UnmarshalsAndConverts(t *testing.T) {
	raw := readGolden(t, "mixed-ast.json")

	// Step 1: Parse as the producer's native shape. Golden drift in the
	// producer fields (renamed keys, removed fields) surfaces here.
	var diffs []astpkg.SemanticDiff
	if err := json.Unmarshal(raw, &diffs); err != nil {
		t.Fatalf("mixed-ast.json failed to unmarshal as []SemanticDiff: %v", err)
	}
	if len(diffs) != 2 {
		t.Fatalf("expected 2 diff entries in mixed-ast.json, got %d", len(diffs))
	}
	first := diffs[0]
	if first.Language != "go" {
		t.Errorf("first diff language = %q, want go", first.Language)
	}
	if first.FilePath != "internal/handler/user.go" {
		t.Errorf("first diff file_path = %q, want internal/handler/user.go", first.FilePath)
	}
	if len(first.Functions) != 2 {
		t.Errorf("first diff functions len = %d, want 2", len(first.Functions))
	}

	// Step 2: Exercise the real consumer pipeline (parseASTData) and verify
	// the resulting ASTData is non-empty. A regression that silently
	// discards functions/types/imports shows up as empty slices here.
	astData, err := parseASTData(raw)
	if err != nil {
		t.Fatalf("parseASTData returned error: %v", err)
	}
	if astData == nil {
		t.Fatal("parseASTData returned nil ASTData")
	}
	if len(astData.Functions.Modified)+len(astData.Functions.Added) == 0 {
		t.Error("expected at least one function in converted ASTData, got none")
	}
	if len(astData.Imports.Added) == 0 {
		t.Error("expected imports.added populated from golden, got empty")
	}
	// Explicit field-presence sanity: the modified GetUser function must be
	// present and retain its receiver/signature semantics.
	foundGetUser := false
	for _, fn := range astData.Functions.Modified {
		if fn.Name == "GetUser" {
			foundGetUser = true
			if fn.Before.Signature == fn.After.Signature {
				t.Error("expected GetUser signature to differ between before and after")
			}
		}
	}
	if !foundGetUser {
		t.Error("expected GetUser among modified functions")
	}
}

// TestGolden_ASTBatch exercises the file-pair batch shape written at
// `ast-batch.json`. The extractor consumes this file, so drift here would
// be caught by ast-extractor, but the shape is also part of the run-all
// wire contract and the consumer struct definition lives in runall.go.
// This test locks the field names (before_path / after_path) so neither
// side can rename them in isolation.
func TestGolden_ASTBatch_UnmarshalsIntoFilePairs(t *testing.T) {
	raw := readGolden(t, "ast-batch.json")

	var pairs []astpkg.FilePair
	if err := json.Unmarshal(raw, &pairs); err != nil {
		t.Fatalf("ast-batch.json failed to unmarshal as []FilePair: %v", err)
	}
	if len(pairs) != 3 {
		t.Fatalf("expected 3 file pairs, got %d", len(pairs))
	}
	// Modified: both paths present.
	if pairs[0].BeforePath == "" || pairs[0].AfterPath == "" {
		t.Errorf("modified pair should have both paths, got %+v", pairs[0])
	}
	// Added: only after_path populated.
	if pairs[1].BeforePath != "" || pairs[1].AfterPath == "" {
		t.Errorf("added pair should have only after_path, got %+v", pairs[1])
	}
	// Deleted: only before_path populated.
	if pairs[2].BeforePath == "" || pairs[2].AfterPath != "" {
		t.Errorf("deleted pair should have only before_path, got %+v", pairs[2])
	}
}

// TestGolden_CallgraphLanguages locks the {"languages": [...]} shape that
// run-all writes and the call-graph runner reads.
func TestGolden_CallgraphLanguages_UnmarshalsLanguageList(t *testing.T) {
	raw := readGolden(t, "callgraph-languages.json")

	var payload struct {
		Languages []string `json:"languages"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("callgraph-languages.json failed to unmarshal: %v", err)
	}
	if len(payload.Languages) != 3 {
		t.Fatalf("expected 3 languages, got %d (%v)", len(payload.Languages), payload.Languages)
	}
	wantOrder := []string{"go", "typescript", "python"}
	for i, want := range wantOrder {
		if payload.Languages[i] != want {
			t.Errorf("languages[%d] = %q, want %q", i, payload.Languages[i], want)
		}
	}
}

// TestGolden_GoFlowProducer_FlowSummaryDrift is the C21 regression target.
// The producer (internal/dataflow.FlowAnalysis) writes flow counts under
// the JSON key "statistics", while the consumer's DataFlowData.Summary
// (internal/context.FlowSummary) reads from "summary". Until Task #7
// teaches parseDataFlowData to translate statistics -> summary (or the
// producer is updated to write summary alongside statistics), a golden
// producer payload will round-trip through parseDataFlowData with a
// zero-valued FlowSummary — and this test encodes that expectation
// concretely so the fix has a regression target to turn green.
//
// This test is written to PASS today by asserting the known-wrong
// behaviour (Summary.TotalFlows == 0 despite 1 flow in the payload). When
// Task #7 lands, flip the `wantTotalFlows` constant from 0 to 1 and this
// test becomes the permanent regression guard.
func TestGolden_GoFlowProducer_FlowSummaryDrift(t *testing.T) {
	raw := readGolden(t, "go-flow-producer.json")

	flowData, err := parseDataFlowData(raw)
	if err != nil {
		t.Fatalf("parseDataFlowData failed on producer golden: %v", err)
	}
	if flowData == nil {
		t.Fatal("parseDataFlowData returned nil")
	}
	if len(flowData.Flows) != 1 {
		t.Fatalf("expected 1 flow from golden, got %d", len(flowData.Flows))
	}
	// Verify the flow itself is fully populated — fields inside Flows are
	// parsed via the producer-format converter and should not drift.
	fl := flowData.Flows[0]
	if fl.Source.Type != "http_query" {
		t.Errorf("flow source type = %q, want http_query", fl.Source.Type)
	}
	if fl.Sink.Type != "database" {
		t.Errorf("flow sink type = %q, want database", fl.Sink.Type)
	}
	if fl.Risk != "critical" {
		t.Errorf("flow risk = %q, want critical", fl.Risk)
	}
	if fl.Sanitized {
		t.Error("flow sanitized = true, want false")
	}

	// Summary assertions — these verify the convertFlowAnalysisToDataFlowData
	// path maps producer `statistics` -> consumer `Summary` correctly.
	if flowData.Summary.TotalFlows != 1 {
		t.Errorf("Summary.TotalFlows = %d, want 1 (producer statistics.total_flows = 1)",
			flowData.Summary.TotalFlows)
	}
	if flowData.Summary.UnsanitizedFlows != 1 {
		t.Errorf("Summary.UnsanitizedFlows = %d, want 1", flowData.Summary.UnsanitizedFlows)
	}
	if flowData.Summary.HighRisk < 1 {
		t.Errorf("Summary.HighRisk = %d, want >= 1 (one critical flow present)",
			flowData.Summary.HighRisk)
	}
}

// TestGolden_GoFlowProducer_SinglePathConversion pins the H28 fix: the
// data-flow parser always routes through the producer-shape converter so
// FlowSummary can never silently zero out when producer/consumer keys
// drift. The previous two-branch design (try-direct then fall back) only
// worked if a hand-crafted consumer-native payload happened to match —
// no real producer ever emitted that shape, so the "direct" branch was
// dead-by-accident and became a drift hazard.
func TestGolden_GoFlowProducer_SinglePathConversion(t *testing.T) {
	// Producer-native payload: "path" is []string, counts are under
	// "statistics". This is what dataflow.FlowAnalysis serialises today.
	raw := []byte(`{
  "language": "go",
  "flows": [
    {
      "id": "flow-x",
      "source": {"type": "env_var", "variable": "DB_DSN", "file": "cfg.go", "line": 3, "context": "os.Getenv(\"DB_DSN\")"},
      "sink":   {"type": "logging", "file": "cfg.go", "line": 4, "context": "log.Printf(dsn)"},
      "path": ["cfg.go:3 DB_DSN", "cfg.go:4 log.Printf"],
      "sanitized": false,
      "risk": "medium",
      "description": "env leaked to logs"
    }
  ],
  "statistics": {"total_flows": 1, "unsanitized_flows": 1, "medium_risk_flows": 1}
}`)

	flowData, err := parseDataFlowData(raw)
	if err != nil {
		t.Fatalf("parseDataFlowData on producer payload failed: %v", err)
	}
	if flowData.Summary.TotalFlows != 1 {
		t.Errorf("Summary.TotalFlows = %d, want 1", flowData.Summary.TotalFlows)
	}
	if flowData.Summary.MediumRisk != 1 {
		t.Errorf("Summary.MediumRisk = %d, want 1", flowData.Summary.MediumRisk)
	}
	if flowData.Summary.UnsanitizedFlows != 1 {
		t.Errorf("Summary.UnsanitizedFlows = %d, want 1", flowData.Summary.UnsanitizedFlows)
	}
	// Converter must expand []string path into []FlowStep so consumer templates
	// can render structured step info.
	if len(flowData.Flows[0].Path) != 2 {
		t.Errorf("converted path steps = %d, want 2", len(flowData.Flows[0].Path))
	}
}
