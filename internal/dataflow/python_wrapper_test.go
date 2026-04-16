package dataflow

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lerianstudio/mithril/internal/testutil"
)

func TestPythonAnalyzerFilterFiles(t *testing.T) {
	py := &PythonAnalyzer{language: "python"}
	ts := &PythonAnalyzer{language: "typescript"}

	files := []string{"a.py", "b.ts", "c.tsx", "d.js", "e.jsx", "f.go"}

	pyFiltered := py.filterFiles(files)
	if len(pyFiltered) != 1 || pyFiltered[0] != "a.py" {
		t.Fatalf("unexpected python filter result: %v", pyFiltered)
	}

	tsFiltered := ts.filterFiles(files)
	if len(tsFiltered) != 4 {
		t.Fatalf("unexpected typescript filter result: %v", tsFiltered)
	}
}

func TestPythonAnalyzerConstructors(t *testing.T) {
	py := NewPythonAnalyzer("/tmp/scripts")
	if py.language != "python" {
		t.Fatalf("python analyzer language = %q, want python", py.language)
	}
	if py.scriptPath == "" {
		t.Fatal("python analyzer script path should not be empty")
	}

	ts := NewTypeScriptAnalyzer("/tmp/scripts")
	if ts.language != "typescript" {
		t.Fatalf("typescript analyzer language = %q, want typescript", ts.language)
	}
	if ts.scriptPath == "" {
		t.Fatal("typescript analyzer script path should not be empty")
	}
}

func TestTypeScriptWrapperUsesTypeScriptLanguageArgument(t *testing.T) {
	testutil.RequirePython3(t)
	tempDir := t.TempDir()
	scriptPath := filepath.Join(tempDir, "inspect_lang.py")
	script := `import json
import sys
print(json.dumps({
  "language": sys.argv[1],
  "sources": [],
  "sinks": [],
  "flows": [],
  "nil_sources": [],
  "statistics": {"total_sources": 0, "total_sinks": 0, "total_flows": 0, "unsanitized_flows": 0, "critical_flows": 0, "high_risk_flows": 0, "nil_risks": 0, "unchecked_nil_risks": 0}
}))
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("failed to write inspect script: %v", err)
	}

	inputFile := filepath.Join(tempDir, "service.ts")
	if err := os.WriteFile(inputFile, []byte("export const x = 1\n"), 0o644); err != nil {
		t.Fatalf("failed to write ts input file: %v", err)
	}

	analyzer := &PythonAnalyzer{scriptPath: scriptPath, language: "typescript"}
	analysis, err := analyzer.Analyze([]string{inputFile})
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if analysis.Language != "typescript" {
		t.Fatalf("expected analyzed language to be typescript, got %q", analysis.Language)
	}
}

func TestPythonAnalyzerRunScript_NoMatchingFiles(t *testing.T) {
	analyzer := &PythonAnalyzer{language: "python", scriptPath: "/does/not/matter.py"}
	analysis, err := analyzer.runScript([]string{"main.go", "README.md"})
	if err != nil {
		t.Fatalf("runScript returned error: %v", err)
	}
	if analysis.Language != "python" {
		t.Fatalf("Language = %q, want python", analysis.Language)
	}
	if len(analysis.Sources) != 0 || len(analysis.Sinks) != 0 || len(analysis.Flows) != 0 {
		t.Fatalf("expected empty analysis for no matching files: %+v", analysis)
	}
}

func TestPythonAnalyzerWrappers_CallScriptAndParse(t *testing.T) {
	testutil.RequirePython3(t)
	tempDir := t.TempDir()
	scriptPath := filepath.Join(tempDir, "mock_data_flow.py")

	script := `import json
import sys

print(json.dumps({
  "language": sys.argv[1],
  "sources": [{"type": "http_query", "file": "service.py", "line": 1, "variable": "id", "pattern": "request.args.get", "context": "id = request.args.get('id')"}],
  "sinks": [{"type": "database", "file": "repo.py", "line": 4, "function": "cursor.execute", "pattern": "cursor.execute", "context": "cursor.execute(query)"}],
  "flows": [{"id": "flow-1", "source": {"type": "http_query", "file": "service.py", "line": 1, "variable": "id", "pattern": "request.args.get"}, "sink": {"type": "database", "file": "repo.py", "line": 4, "function": "cursor.execute", "pattern": "cursor.execute"}, "path": ["service.py:1", "repo.py:4"], "sanitized": False, "risk": "critical", "description": "unsanitized"}],
  "nil_sources": [],
  "statistics": {"total_sources": 1, "total_sinks": 1, "total_flows": 1, "unsanitized_flows": 1, "critical_flows": 1, "high_risk_flows": 0, "nil_risks": 0, "unchecked_nil_risks": 0}
}))
`

	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("failed to write mock script: %v", err)
	}

	inputFile := filepath.Join(tempDir, "service.py")
	if err := os.WriteFile(inputFile, []byte("print('ok')\n"), 0o644); err != nil {
		t.Fatalf("failed to write input file: %v", err)
	}

	analyzer := &PythonAnalyzer{scriptPath: scriptPath, language: "python"}

	sources, err := analyzer.DetectSources([]string{inputFile})
	if err != nil {
		t.Fatalf("DetectSources returned error: %v", err)
	}
	if len(sources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(sources))
	}

	sinks, err := analyzer.DetectSinks([]string{inputFile})
	if err != nil {
		t.Fatalf("DetectSinks returned error: %v", err)
	}
	if len(sinks) != 1 {
		t.Fatalf("expected 1 sink, got %d", len(sinks))
	}

	flows, err := analyzer.TrackFlows(nil, nil, []string{inputFile})
	if err != nil {
		t.Fatalf("TrackFlows returned error: %v", err)
	}
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}

	analysis, err := analyzer.Analyze([]string{inputFile})
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if analysis.Statistics.TotalFlows != 1 {
		t.Fatalf("expected TotalFlows=1, got %d", analysis.Statistics.TotalFlows)
	}
}

func TestPythonAnalyzerRunScript_PropagatesScriptErrors(t *testing.T) {
	testutil.RequirePython3(t)
	tempDir := t.TempDir()
	scriptPath := filepath.Join(tempDir, "error_script.py")
	script := `import sys
print("boom", file=sys.stderr)
raise SystemExit(1)
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("failed to write error script: %v", err)
	}

	inputFile := filepath.Join(tempDir, "service.py")
	if err := os.WriteFile(inputFile, []byte("print('ok')\n"), 0o644); err != nil {
		t.Fatalf("failed to write input file: %v", err)
	}

	analyzer := &PythonAnalyzer{scriptPath: scriptPath, language: "python"}
	_, err := analyzer.runScript([]string{inputFile})
	if err == nil {
		t.Fatal("expected script failure error")
	}
	if !strings.Contains(err.Error(), "script execution failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPythonAnalyzerRunScript_InvalidJSON(t *testing.T) {
	testutil.RequirePython3(t)
	tempDir := t.TempDir()
	scriptPath := filepath.Join(tempDir, "invalid_json.py")
	script := `print("not-json")
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("failed to write invalid json script: %v", err)
	}

	inputFile := filepath.Join(tempDir, "service.py")
	if err := os.WriteFile(inputFile, []byte("print('ok')\n"), 0o644); err != nil {
		t.Fatalf("failed to write input file: %v", err)
	}

	analyzer := &PythonAnalyzer{scriptPath: scriptPath, language: "python"}
	_, err := analyzer.runScript([]string{inputFile})
	if err == nil {
		t.Fatal("expected JSON parsing error")
	}
	if !strings.Contains(err.Error(), "parsing script output") {
		t.Fatalf("unexpected error: %v", err)
	}
}
