package mithrilcli

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRunAllFlags(t *testing.T) {
	tests := []struct {
		name            string
		args            []string
		wantErr         bool
		wantCompare     bool
		wantBase        string
		wantHead        string
		wantErrContains string
	}{
		{
			name:        "defaults to compare mode",
			args:        nil,
			wantCompare: true,
			wantBase:    "main",
			wantHead:    "HEAD",
		},
		{
			name:        "base implies compare",
			args:        []string{"--base=develop"},
			wantCompare: true,
			wantBase:    "develop",
			wantHead:    "HEAD",
		},
		{
			name:        "staged mode clears refs",
			args:        []string{"--staged"},
			wantCompare: false,
			wantBase:    "",
			wantHead:    "",
		},
		{
			name:        "all-modified mode clears refs",
			args:        []string{"--all-modified"},
			wantCompare: false,
			wantBase:    "",
			wantHead:    "",
		},
		{
			name:            "rejects mutually exclusive modes",
			args:            []string{"--staged", "--unstaged"},
			wantErr:         true,
			wantErrContains: "choose only one mode",
		},
		{
			name:            "rejects files with refs",
			args:            []string{"--files=a.go", "--base=main"},
			wantErr:         true,
			wantErrContains: "choose only one mode",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("run-all", flag.ContinueOnError)
			var stderr bytes.Buffer
			fs.SetOutput(&stderr)

			cfg := &runAllConfig{}
			fs.StringVar(&cfg.baseRef, "base", "main", "")
			fs.StringVar(&cfg.headRef, "head", "HEAD", "")
			fs.BoolVar(&cfg.compare, "compare", false, "")
			fs.BoolVar(&cfg.staged, "staged", false, "")
			fs.StringVar(&cfg.files, "files", "", "")
			fs.StringVar(&cfg.filesFrom, "files-from", "", "")
			fs.BoolVar(&cfg.unstaged, "unstaged", false, "")
			fs.BoolVar(&cfg.allMod, "all-modified", false, "")

			if err := fs.Parse(tc.args); err != nil {
				t.Fatalf("parse failed: %v", err)
			}

			err := validateRunAllFlags(fs, cfg, &stderr)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				if tc.wantErrContains != "" && !strings.Contains(stderr.String(), tc.wantErrContains) {
					t.Fatalf("stderr %q does not contain %q", stderr.String(), tc.wantErrContains)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.compare != tc.wantCompare {
				t.Fatalf("compare=%v want %v", cfg.compare, tc.wantCompare)
			}
			if cfg.baseRef != tc.wantBase {
				t.Fatalf("baseRef=%q want %q", cfg.baseRef, tc.wantBase)
			}
			if cfg.headRef != tc.wantHead {
				t.Fatalf("headRef=%q want %q", cfg.headRef, tc.wantHead)
			}
		})
	}
}

// ============================================================================
// parseSkipList unit tests (ported from cmd/run-all/main_test.go).
// ============================================================================

func TestParseSkipList_Empty(t *testing.T) {
	result := parseSkipList("")
	if len(result) != 0 {
		t.Errorf("expected empty map, got %d entries: %v", len(result), result)
	}
}

func TestParseSkipList_Single(t *testing.T) {
	result := parseSkipList("scope")
	if len(result) != 1 || !result["scope"] {
		t.Fatalf("expected {scope:true}, got %v", result)
	}
}

func TestParseSkipList_Multiple(t *testing.T) {
	result := parseSkipList("scope,ast,callgraph")
	for _, phase := range []string{"scope", "ast", "callgraph"} {
		if !result[phase] {
			t.Errorf("missing phase %q", phase)
		}
	}
	if len(result) != 3 {
		t.Errorf("expected 3 entries, got %d: %v", len(result), result)
	}
}

func TestParseSkipList_Whitespace(t *testing.T) {
	result := parseSkipList(" scope , ast ")
	if !result["scope"] || !result["ast"] {
		t.Fatalf("trimmed names missing: %v", result)
	}
	if result[" scope "] {
		t.Error("whitespace should be trimmed")
	}
}

func TestParseSkipList_AllPhases(t *testing.T) {
	result := parseSkipList("scope,static-analysis,ast,callgraph,dataflow,context")
	for _, phase := range []string{"scope", "static-analysis", "ast", "callgraph", "dataflow", "context"} {
		if !result[phase] {
			t.Errorf("missing phase %q", phase)
		}
	}
}

func TestParseSkipList_EmptyEntries(t *testing.T) {
	result := parseSkipList("scope,,ast,")
	if len(result) != 2 {
		t.Errorf("expected 2 entries (empties ignored), got %d", len(result))
	}
}

func TestParseSkipList_InvalidPhase(t *testing.T) {
	var buf bytes.Buffer
	result := parseSkipListWithWarnings("scope,unknown-phase,ast", &buf)
	if !result["scope"] || !result["ast"] {
		t.Error("valid phases should still be parsed")
	}
	if !result["unknown-phase"] {
		t.Error("unknown phase should still be recorded")
	}
	if !strings.Contains(buf.String(), "unknown phase") || !strings.Contains(buf.String(), "unknown-phase") {
		t.Errorf("expected warning about unknown phase, got %q", buf.String())
	}
}

// ============================================================================
// Skip-condition unit tests (ported from cmd/run-all/main_test.go).
// ============================================================================

func TestShouldSkipForNoFiles_MissingScope(t *testing.T) {
	cfg := &runAllConfig{outputDir: t.TempDir()}
	skip, reason := shouldSkipForNoFiles(cfg)
	if !skip {
		t.Fatal("expected skip when scope.json is missing")
	}
	if !strings.Contains(reason, "scope.json") {
		t.Fatalf("unexpected reason: %q", reason)
	}
}

func TestShouldSkipForNoFiles_EmptyScope(t *testing.T) {
	dir := t.TempDir()
	writeScopeForTest(t, dir, "go", nil, nil, nil)
	cfg := &runAllConfig{outputDir: dir}
	skip, reason := shouldSkipForNoFiles(cfg)
	if !skip {
		t.Fatal("expected skip when no files present")
	}
	if reason != "No changed files detected" {
		t.Fatalf("unexpected reason: %q", reason)
	}
}

func TestShouldSkipForMissingScope(t *testing.T) {
	cfg := &runAllConfig{outputDir: t.TempDir()}
	skip, reason := shouldSkipForMissingScope(cfg)
	if !skip {
		t.Fatal("expected skip when scope.json missing")
	}
	if !strings.Contains(reason, "scope.json") {
		t.Fatalf("unexpected reason: %q", reason)
	}
}

func TestShouldSkipForNoFilesOrUnknownLanguage_UsesNoFilesReason(t *testing.T) {
	dir := t.TempDir()
	writeScopeForTest(t, dir, "unknown", nil, nil, nil)
	cfg := &runAllConfig{outputDir: dir}
	skip, reason := shouldSkipForNoFilesOrUnknownLanguage(cfg)
	if !skip {
		t.Fatal("expected skip when no files")
	}
	if reason != "No changed files detected" {
		t.Fatalf("unexpected reason: %q", reason)
	}
}

func TestShouldSkipForNoFilesOrUnknownLanguage_UnknownLanguage(t *testing.T) {
	dir := t.TempDir()
	writeScopeForTest(t, dir, "unknown", []string{"main.go"}, nil, nil)
	cfg := &runAllConfig{outputDir: dir}
	skip, reason := shouldSkipForNoFilesOrUnknownLanguage(cfg)
	if !skip {
		t.Fatal("expected skip when language unknown")
	}
	if reason != "Unknown language detected" {
		t.Fatalf("unexpected reason: %q", reason)
	}
}

// ============================================================================
// extractFileFromGit tests (ported, with H20 post-join containment assertion).
// ============================================================================

func TestExtractFileFromGit_Success(t *testing.T) {
	tempDir := t.TempDir()
	path, err := extractFileFromGit("HEAD", "main.go", tempDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(filepath.Clean(path), filepath.Clean(tempDir)+string(filepath.Separator)) {
		t.Fatalf("expected file inside temp dir, got %s", path)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("extracted file missing: %v", err)
	}
}

func TestExtractFileFromGit_InvalidPaths(t *testing.T) {
	tempDir := t.TempDir()
	tests := []struct {
		name      string
		filePath  string
		errSubstr string
	}{
		{"empty", "", "invalid file path: empty"},
		{"absolute", filepath.Join(tempDir, "x.go"), "absolute paths are not allowed"},
		{"traversal", "../README.md", "contains path traversal"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := extractFileFromGit("HEAD", tc.filePath, tempDir)
			if err == nil {
				t.Fatalf("expected error")
			}
			if !strings.Contains(err.Error(), tc.errSubstr) {
				t.Fatalf("expected %q in error, got %v", tc.errSubstr, err)
			}
		})
	}
}

func TestExtractFileFromGit_GitShowFailure(t *testing.T) {
	tempDir := t.TempDir()
	_, err := extractFileFromGit("HEAD", "no-such-file-xyz.txt", tempDir)
	if err == nil {
		t.Fatal("expected error for missing file in git")
	}
	if !strings.Contains(err.Error(), "git show failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ============================================================================
// generateASTBatchFile tests (ported; these also enforce H21 — temp dir MUST
// be under outputDir so ast.NewPathValidator confinement accepts the paths).
// ============================================================================

func TestGenerateASTBatchFile(t *testing.T) {
	dir := t.TempDir()
	scopeData := map[string]interface{}{
		"base_ref":  "HEAD",
		"head_ref":  "HEAD",
		"language":  "go",
		"languages": []string{"go"},
		"files": map[string]interface{}{
			"modified": []string{"main.go"},
			"added":    []string{"new_file.go"},
			"deleted":  []string{"main.go"},
		},
	}
	writeJSONForTest(t, filepath.Join(dir, "scope.json"), scopeData)

	cfg := &runAllConfig{outputDir: dir, baseRef: "HEAD", verbose: true}
	batchPath, tempDir, err := generateASTBatchFile(cfg)
	if err != nil {
		t.Fatalf("generateASTBatchFile returned error: %v", err)
	}
	if batchPath == "" {
		t.Fatal("empty batchPath")
	}
	if !strings.HasPrefix(filepath.Clean(tempDir), filepath.Clean(dir)+string(filepath.Separator)) {
		t.Fatalf("expected AST temp dir under output dir, got %s", tempDir)
	}

	content, err := os.ReadFile(batchPath)
	if err != nil {
		t.Fatalf("failed to read batch file: %v", err)
	}
	var pairs []filePair
	if err := json.Unmarshal(content, &pairs); err != nil {
		t.Fatalf("failed to parse batch file: %v", err)
	}
	if len(pairs) != 3 {
		t.Fatalf("expected 3 pairs, got %d", len(pairs))
	}
}

func TestGenerateASTBatchFile_ModifiedExtractionFailure(t *testing.T) {
	dir := t.TempDir()
	before := listASTTempDirs(t, dir)
	scopeData := map[string]interface{}{
		"base_ref":  "HEAD",
		"head_ref":  "HEAD",
		"language":  "go",
		"languages": []string{"go"},
		"files": map[string]interface{}{
			"modified": []string{"no-such-file.go"},
			"added":    []string{},
			"deleted":  []string{},
		},
	}
	writeJSONForTest(t, filepath.Join(dir, "scope.json"), scopeData)

	cfg := &runAllConfig{outputDir: dir, baseRef: "HEAD"}
	_, _, err := generateASTBatchFile(cfg)
	if err == nil {
		t.Fatal("expected extraction failure")
	}
	if !strings.Contains(err.Error(), "failed to extract") {
		t.Fatalf("unexpected error: %v", err)
	}
	after := listASTTempDirs(t, dir)
	if len(after) != len(before) {
		t.Fatalf("expected no leaked temp dirs on failure (before=%d after=%d)", len(before), len(after))
	}
}

func TestGenerateASTBatchFile_UsesScopeBaseRefOverConfigBaseRef(t *testing.T) {
	dir := t.TempDir()
	scopeData := map[string]interface{}{
		"base_ref":  "missing-ref-for-test",
		"head_ref":  "HEAD",
		"language":  "go",
		"languages": []string{"go"},
		"files": map[string]interface{}{
			"modified": []string{"main.go"},
			"added":    []string{},
			"deleted":  []string{},
		},
	}
	writeJSONForTest(t, filepath.Join(dir, "scope.json"), scopeData)

	cfg := &runAllConfig{outputDir: dir, baseRef: "HEAD"}
	_, _, err := generateASTBatchFile(cfg)
	if err == nil {
		t.Fatal("expected error when scope base_ref is invalid")
	}
	if !strings.Contains(err.Error(), "missing-ref-for-test") {
		t.Fatalf("expected scope base_ref in error, got %v", err)
	}
}

func TestGenerateASTBatchFile_DeletedExtractionFailureContinues(t *testing.T) {
	dir := t.TempDir()
	scopeData := map[string]interface{}{
		"base_ref":  "HEAD",
		"head_ref":  "HEAD",
		"language":  "go",
		"languages": []string{"go"},
		"files": map[string]interface{}{
			"modified": []string{},
			"added":    []string{"new_file.go"},
			"deleted":  []string{"no-such-deleted.go"},
		},
	}
	writeJSONForTest(t, filepath.Join(dir, "scope.json"), scopeData)

	cfg := &runAllConfig{outputDir: dir, baseRef: "HEAD", verbose: true}
	batchPath, _, err := generateASTBatchFile(cfg)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	content, err := os.ReadFile(batchPath)
	if err != nil {
		t.Fatalf("failed to read batch file: %v", err)
	}
	var pairs []filePair
	if err := json.Unmarshal(content, &pairs); err != nil {
		t.Fatalf("failed to parse batch file: %v", err)
	}
	if len(pairs) != 1 {
		t.Fatalf("expected only added file pair, got %d", len(pairs))
	}
	if pairs[0].AfterPath != "new_file.go" || pairs[0].BeforePath != "" {
		t.Fatalf("unexpected pair: %+v", pairs[0])
	}
}

// ============================================================================
// Run-level tests (ported; now in-process).
// ============================================================================

func TestRunAll_AllPhasesSkipped(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "out")
	var stderr bytes.Buffer
	err := runAll(
		[]string{"--output=" + outDir, "--skip=scope,static-analysis,ast,callgraph,dataflow,context"},
		&bytes.Buffer{}, &stderr,
	)
	if err != nil {
		t.Fatalf("expected success, got %v\nstderr: %s", err, stderr.String())
	}
	for _, want := range []string{
		"[SKIP] scope", "[SKIP] static-analysis", "[SKIP] ast",
		"[SKIP] callgraph", "[SKIP] dataflow", "[SKIP] context",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr missing %q\nstderr: %s", want, stderr.String())
		}
	}
}

func TestRunAll_OutputDirCreation(t *testing.T) {
	base := t.TempDir()
	nested := filepath.Join(base, "nested", "deeply", "output")
	err := runAll(
		[]string{"--output=" + nested, "--skip=scope,static-analysis,ast,callgraph,dataflow,context"},
		&bytes.Buffer{}, &bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(nested); os.IsNotExist(err) {
		t.Errorf("nested output dir not created: %s", nested)
	}
}

func TestRunAll_VerboseOutput(t *testing.T) {
	dir := t.TempDir()
	var stderr bytes.Buffer
	err := runAll(
		[]string{"--output=" + dir, "--verbose", "--skip=scope,static-analysis,ast,callgraph,dataflow,context"},
		&bytes.Buffer{}, &stderr,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{"Configuration:", "Base ref:", "Head ref:", "Output directory:"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("verbose stderr missing %q\nstderr: %s", want, stderr.String())
		}
	}
}

// ============================================================================
// Helpers.
// ============================================================================

func writeScopeForTest(t *testing.T, dir, language string, modified, added, deleted []string) {
	t.Helper()
	if modified == nil {
		modified = []string{}
	}
	if added == nil {
		added = []string{}
	}
	if deleted == nil {
		deleted = []string{}
	}
	data := map[string]interface{}{
		"base_ref":  "main",
		"head_ref":  "HEAD",
		"language":  language,
		"languages": []string{language},
		"files": map[string]interface{}{
			"modified": modified,
			"added":    added,
			"deleted":  deleted,
		},
	}
	writeJSONForTest(t, filepath.Join(dir, "scope.json"), data)
}

func writeJSONForTest(t *testing.T, path string, data interface{}) {
	t.Helper()
	content, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func listASTTempDirs(t *testing.T, parentDir string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(parentDir, "ast-before-*"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	return matches
}
