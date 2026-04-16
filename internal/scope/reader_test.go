package scope

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/lerianstudio/mithril/internal/lint"
)

func TestReadScopeJSON(t *testing.T) {
	tempDir := t.TempDir()
	scopePath := filepath.Join(tempDir, "scope.json")

	content := `{
		"base_ref": "main",
		"head_ref": "HEAD",
		"language": "go",
		"languages": ["go", "python"],
		"files": {"modified": ["./cmd/main.go"], "added": [".\\py\\app.py"], "deleted": []},
		"stats": {"total_files": 2, "total_additions": 10, "total_deletions": 2},
		"packages_affected": ["cmd"]
	}`
	if err := os.WriteFile(scopePath, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write scope file: %v", err)
	}

	scope, err := ReadScopeJSON(scopePath)
	if err != nil {
		t.Fatalf("ReadScopeJSON failed: %v", err)
	}

	if scope.BaseRef != "main" || scope.HeadRef != "HEAD" {
		t.Fatalf("unexpected refs: base=%s head=%s", scope.BaseRef, scope.HeadRef)
	}
	if scope.GetLanguage() != lint.LanguageGo {
		t.Fatalf("expected go language, got %s", scope.GetLanguage())
	}

	allFiles := scope.GetAnalyzableFiles()
	if len(allFiles) != 2 {
		t.Fatalf("expected 2 files, got %d", len(allFiles))
	}
	if allFiles[0] != "cmd/main.go" {
		t.Fatalf("expected normalized modified file path, got %q", allFiles[0])
	}

	if runtime.GOOS == "windows" {
		if allFiles[1] == ".\\py\\app.py" {
			t.Fatalf("expected normalized added file path, got %q", allFiles[1])
		}
	}

	fileMap := scope.GetAnalyzableFilesMap()
	if !fileMap["cmd/main.go"] {
		t.Fatal("expected normalized modified file to be present in map")
	}

	packages := scope.GetPackages()
	if len(packages) != 1 || packages[0] != "cmd" {
		t.Fatalf("unexpected packages: %v", packages)
	}
}

func TestReadScopeJSON_NormalizesOptionalFields(t *testing.T) {
	tempDir := t.TempDir()
	scopePath := filepath.Join(tempDir, "scope.json")

	content := `{"base_ref":"main","head_ref":"HEAD","language":"go","files":{},"stats":{}}`
	if err := os.WriteFile(scopePath, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write scope file: %v", err)
	}

	scope, err := ReadScopeJSON(scopePath)
	if err != nil {
		t.Fatalf("ReadScopeJSON failed: %v", err)
	}

	if scope.Languages == nil || scope.Packages == nil {
		t.Fatal("expected optional slices to be initialized")
	}
	if scope.Files.Modified == nil || scope.Files.Added == nil || scope.Files.Deleted == nil {
		t.Fatal("expected file slices to be initialized")
	}
}

func TestReadScopeJSON_Errors(t *testing.T) {
	if _, err := ReadScopeJSON(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("expected missing file to fail")
	}

	tempDir := t.TempDir()
	invalidPath := filepath.Join(tempDir, "scope.json")
	if err := os.WriteFile(invalidPath, []byte("{"), 0o644); err != nil {
		t.Fatalf("failed to write invalid scope file: %v", err)
	}

	if _, err := ReadScopeJSON(invalidPath); err == nil {
		t.Fatal("expected invalid json to fail")
	}
}

func TestNormalizeLanguage(t *testing.T) {
	tests := map[string]lint.Language{
		"go":         lint.LanguageGo,
		"GOLANG":     lint.LanguageGo,
		"ts":         lint.LanguageTypeScript,
		"javascript": lint.LanguageTypeScript,
		"Py":         lint.LanguagePython,
		"mixed":      lint.LanguageMixed,
		"unknown":    lint.Language(""),
	}

	for input, expected := range tests {
		if got := NormalizeLanguage(input); got != expected {
			t.Fatalf("NormalizeLanguage(%q) = %q, want %q", input, got, expected)
		}
	}
}

func TestGetAnalyzableVsAllChangedFiles(t *testing.T) {
	s := &ScopeJSON{
		Files: FilesByStatus{
			Modified: []string{"a/mod.go"},
			Added:    []string{"a/add.go"},
			Deleted:  []string{"a/del.go"},
			Renamed:  []RenamedFile{{OldPath: "a/old.go", NewPath: "a/new.go"}},
		},
	}

	analyzable := s.GetAnalyzableFiles()
	if len(analyzable) != 2 {
		t.Fatalf("GetAnalyzableFiles: got %v, want 2 entries (mod+add only)", analyzable)
	}
	for _, f := range analyzable {
		if f == "a/del.go" {
			t.Fatalf("GetAnalyzableFiles must exclude Deleted: %v", analyzable)
		}
	}

	all := s.GetAllChangedFiles()
	wantPresent := []string{"a/mod.go", "a/add.go", "a/del.go", "a/old.go", "a/new.go"}
	for _, w := range wantPresent {
		found := false
		for _, f := range all {
			if f == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("GetAllChangedFiles missing %q: got %v", w, all)
		}
	}

	deleted := s.GetDeletedFiles()
	if len(deleted) != 1 || deleted[0] != "a/del.go" {
		t.Fatalf("GetDeletedFiles: got %v, want [a/del.go]", deleted)
	}
}

func TestGetAllChangedFilesNilSafe(t *testing.T) {
	var s *ScopeJSON
	if got := s.GetAllChangedFiles(); len(got) != 0 {
		t.Errorf("nil receiver: got %v, want empty", got)
	}
	if got := s.GetAnalyzableFiles(); len(got) != 0 {
		t.Errorf("nil receiver: got %v, want empty", got)
	}
	if got := s.GetDeletedFiles(); len(got) != 0 {
		t.Errorf("nil receiver: got %v, want empty", got)
	}
}

func TestDefaultScopePath(t *testing.T) {
	projectDir := "/tmp/project"
	expected := filepath.Join(projectDir, ".ring", "codereview", "scope.json")
	if got := DefaultScopePath(projectDir); got != expected {
		t.Fatalf("DefaultScopePath() = %q, want %q", got, expected)
	}
}
