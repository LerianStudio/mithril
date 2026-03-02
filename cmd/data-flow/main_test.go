package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/lerianstudio/mithril/internal/dataflow"
)

func TestLoadScope_LanguagesArray(t *testing.T) {
	workDir := t.TempDir()
	scopePath := filepath.Join(workDir, "scope.json")

	raw := map[string]interface{}{
		"languages": []string{"go", "typescript"},
		"files": map[string]interface{}{
			"modified": []string{"cmd/app/main.go", "web/app.ts"},
			"added":    []string{"web/new.tsx"},
			"deleted":  []string{},
		},
	}

	requireScopeFile(t, workDir, "cmd/app/main.go")
	requireScopeFile(t, workDir, "web/app.ts")
	requireScopeFile(t, workDir, "web/new.tsx")
	writeScopeFixture(t, scopePath, raw)

	scope, err := loadScope(scopePath, workDir)
	if err != nil {
		t.Fatalf("loadScope returned error: %v", err)
	}

	if len(scope.Languages) != 2 {
		t.Fatalf("expected 2 languages, got %d", len(scope.Languages))
	}

	goFiles := getFilesForLanguage(scope, "go")
	if len(goFiles) != 1 {
		t.Fatalf("expected 1 go file, got %d", len(goFiles))
	}

	tsFiles := getFilesForLanguage(scope, "typescript")
	if len(tsFiles) != 2 {
		t.Fatalf("expected 2 typescript files, got %d", len(tsFiles))
	}
}

func TestLoadScope_LanguagesMapCompatibility(t *testing.T) {
	workDir := t.TempDir()
	scopePath := filepath.Join(workDir, "scope-map.json")

	raw := map[string]interface{}{
		"languages": map[string][]string{
			"go":         {"cmd/app/main.go"},
			"typescript": {"web/app.ts"},
		},
		"files": map[string]interface{}{
			"modified": []string{"cmd/app/main.go", "web/app.ts"},
			"added":    []string{},
			"deleted":  []string{},
		},
	}

	requireScopeFile(t, workDir, "cmd/app/main.go")
	requireScopeFile(t, workDir, "web/app.ts")
	writeScopeFixture(t, scopePath, raw)

	scope, err := loadScope(scopePath, workDir)
	if err != nil {
		t.Fatalf("loadScope returned error: %v", err)
	}

	sort.Strings(scope.Languages)
	expected := []string{"go", "typescript"}
	if len(scope.Languages) != len(expected) {
		t.Fatalf("expected %d languages, got %d", len(expected), len(scope.Languages))
	}
	for i, lang := range expected {
		if scope.Languages[i] != lang {
			t.Fatalf("expected language %q at index %d, got %q", lang, i, scope.Languages[i])
		}
	}

	if len(scope.FilesByLanguage["go"]) != 1 {
		t.Fatalf("expected 1 go language-indexed file, got %d", len(scope.FilesByLanguage["go"]))
	}
}

func TestLoadScope_RejectsTraversalPaths(t *testing.T) {
	workDir := t.TempDir()
	scopePath := filepath.Join(workDir, "scope-traversal.json")

	raw := map[string]interface{}{
		"languages": []string{"go"},
		"files": map[string]interface{}{
			"modified": []string{"../etc/passwd", "cmd/app/main.go"},
			"added":    []string{},
			"deleted":  []string{},
		},
	}

	requireScopeFile(t, workDir, "cmd/app/main.go")
	writeScopeFixture(t, scopePath, raw)

	_, err := loadScope(scopePath, workDir)
	if err == nil {
		t.Fatal("expected traversal path to fail scope loading")
	}
	if !strings.Contains(err.Error(), "invalid scope file path") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_JSONOnlyWithNoFiles(t *testing.T) {
	workDir := t.TempDir()
	scopeFile := filepath.Join(workDir, "scope.json")
	output := filepath.Join(workDir, "out")
	if err := os.MkdirAll(output, 0o755); err != nil {
		t.Fatalf("failed to create output directory: %v", err)
	}

	writeScopeFixture(t, scopeFile, map[string]interface{}{
		"languages": []string{"go"},
		"files": map[string]interface{}{
			"modified": []string{},
			"added":    []string{},
			"deleted":  []string{},
		},
	})

	restore := setRunFlags(scopeFile, output, workDir, "", true, false)
	defer restore()

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	runErr := run()
	if err := w.Close(); err != nil {
		t.Fatalf("failed to close stdout pipe: %v", err)
	}
	if runErr != nil {
		t.Fatalf("run returned error: %v", runErr)
	}
	outputBytes, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("failed to read run output: %v", err)
	}
	if !strings.Contains(string(outputBytes), "\"languages\"") {
		t.Fatalf("expected JSON output for --json mode, got %q", string(outputBytes))
	}
}

func TestRun_UnsupportedLanguage(t *testing.T) {
	workDir := t.TempDir()
	scopeFile := filepath.Join(workDir, "scope.json")
	writeScopeFixture(t, scopeFile, map[string]interface{}{
		"languages": []string{"go"},
		"files": map[string]interface{}{
			"modified": []string{},
			"added":    []string{},
			"deleted":  []string{},
		},
	})

	restore := setRunFlags(scopeFile, workDir, workDir, "rust", true, false)
	defer restore()

	err := run()
	if err == nil {
		t.Fatal("expected unsupported language error")
	}
	if !strings.Contains(err.Error(), "unsupported language") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWriteJSON_CreatesParentDir(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "nested", "result.json")

	err := writeJSON(path, map[string]string{"status": "ok"})
	if err != nil {
		t.Fatalf("writeJSON returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read json output: %v", err)
	}
	if !strings.Contains(string(data), "status") {
		t.Fatalf("unexpected json content: %s", string(data))
	}
}

func TestPrintSummary_HandlesNilAnalysis(t *testing.T) {
	results := map[string]*dataflow.FlowAnalysis{
		"go": nil,
	}

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	printSummary(results)
	if err := w.Close(); err != nil {
		t.Fatalf("failed to close stdout pipe: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("failed to read summary output: %v", err)
	}
	if !strings.Contains(string(out), "Data flow analysis complete") {
		t.Fatalf("unexpected summary output: %s", string(out))
	}
}

func TestNormalizeLanguage(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{input: "go", expected: "go"},
		{input: "golang", expected: "go"},
		{input: "py", expected: "python"},
		{input: "javascript", expected: "typescript"},
		{input: "RUST", expected: ""},
	}

	for _, tt := range tests {
		if got := normalizeLanguage(tt.input); got != tt.expected {
			t.Fatalf("normalizeLanguage(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestDetectLanguage(t *testing.T) {
	tests := []struct {
		file     string
		expected string
	}{
		{file: "main.go", expected: "go"},
		{file: "service.py", expected: "python"},
		{file: "app.tsx", expected: "typescript"},
		{file: "README.md", expected: ""},
	}

	for _, tt := range tests {
		if got := detectLanguage(tt.file); got != tt.expected {
			t.Fatalf("detectLanguage(%q) = %q, want %q", tt.file, got, tt.expected)
		}
	}
}

func setRunFlags(scope, output, scripts, lang string, jsonMode bool, verboseMode bool) func() {
	prevScope := *scopePath
	prevOutput := *outputDir
	prevScripts := *scriptDir
	prevLang := *language
	prevJSON := *jsonOnly
	prevVerbose := *verbose

	*scopePath = scope
	*outputDir = output
	*scriptDir = scripts
	*language = lang
	*jsonOnly = jsonMode
	*verbose = verboseMode

	return func() {
		*scopePath = prevScope
		*outputDir = prevOutput
		*scriptDir = prevScripts
		*language = prevLang
		*jsonOnly = prevJSON
		*verbose = prevVerbose
	}
}

func writeScopeFixture(t *testing.T, path string, raw map[string]interface{}) {
	t.Helper()
	bytes, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("failed to marshal scope fixture: %v", err)
	}
	if err := os.WriteFile(path, bytes, 0o644); err != nil {
		t.Fatalf("failed to write scope fixture: %v", err)
	}
}

func requireScopeFile(t *testing.T, workDir, relPath string) {
	t.Helper()
	absPath := filepath.Join(workDir, relPath)
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		t.Fatalf("failed to create fixture directories: %v", err)
	}
	if err := os.WriteFile(absPath, []byte("package main\n"), 0o644); err != nil {
		t.Fatalf("failed to write fixture file: %v", err)
	}
}
