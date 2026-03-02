package scope

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestExpandFilePatterns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping glob tests on Windows path handling")
	}

	baseDir := t.TempDir()
	mustWriteFile(t, filepath.Join(baseDir, "cmd", "app", "main.go"))
	mustWriteFile(t, filepath.Join(baseDir, "cmd", "app", "util.go"))
	mustWriteFile(t, filepath.Join(baseDir, "web", "app.ts"))
	mustWriteFile(t, filepath.Join(baseDir, "README.md"))

	files, err := ExpandFilePatterns(baseDir, []string{"cmd/**/*.go", "web/*.ts"})
	if err != nil {
		t.Fatalf("ExpandFilePatterns() error: %v", err)
	}

	if len(files) != 3 {
		t.Fatalf("expected 3 files, got %d: %v", len(files), files)
	}
}

func TestExpandFilePatterns_NoMatches(t *testing.T) {
	baseDir := t.TempDir()
	files, err := ExpandFilePatterns(baseDir, []string{"missing/*.go"})
	if err != nil {
		t.Fatalf("unexpected error for unmatched pattern: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("expected empty result for unmatched pattern, got %v", files)
	}
}

func TestExpandFilePatterns_PathTraversal(t *testing.T) {
	baseDir := t.TempDir()
	_, err := ExpandFilePatterns(baseDir, []string{"../*.go"})
	if err == nil {
		t.Fatal("expected error for traversal pattern")
	}
}

func TestValidatePattern(t *testing.T) {
	absPattern := filepath.Join(string(filepath.Separator), "tmp", "*.go")

	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		{name: "valid simple pattern", pattern: "internal/*.go", wantErr: false},
		{name: "valid recursive pattern", pattern: "cmd/**/*.go", wantErr: false},
		{name: "empty pattern", pattern: "", wantErr: true},
		{name: "dot pattern", pattern: ".", wantErr: true},
		{name: "absolute pattern", pattern: absPattern, wantErr: true},
		{name: "unix traversal", pattern: "../*.go", wantErr: true},
		{name: "nested traversal", pattern: "foo/../../bar/*.go", wantErr: true},
		{name: "windows traversal", pattern: "..\\*.go", wantErr: true},
		{name: "null byte", pattern: "src\x00/*.go", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePattern(tt.pattern)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("validatePattern(%q) expected error", tt.pattern)
				}
				return
			}
			if err != nil {
				t.Fatalf("validatePattern(%q) unexpected error: %v", tt.pattern, err)
			}
		})
	}
}

func mustWriteFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}
	if err := os.WriteFile(path, []byte("data"), 0o644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
}
