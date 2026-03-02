package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lerianstudio/mithril/internal/lint"
)

func TestWriteLanguageResult_ValidLanguageToken(t *testing.T) {
	outDir := t.TempDir()
	w := NewLintWriter(outDir)

	if err := w.WriteLanguageResult(lint.Language("go"), lint.NewResult()); err != nil {
		t.Fatalf("WriteLanguageResult returned error: %v", err)
	}

	outputPath := filepath.Join(outDir, "go-lint.json")
	if _, err := os.Stat(outputPath); err != nil {
		t.Fatalf("expected output file %q to exist: %v", outputPath, err)
	}
}

func TestWriteLanguageResult_RejectsPathTraversalToken(t *testing.T) {
	outDir := t.TempDir()
	w := NewLintWriter(outDir)

	err := w.WriteLanguageResult(lint.Language("../../etc/passwd"), lint.NewResult())
	if err == nil {
		t.Fatal("expected error for traversal language token, got nil")
	}

	if !strings.Contains(err.Error(), "path separators") {
		t.Fatalf("expected path separator validation error, got: %v", err)
	}

	entries, readErr := os.ReadDir(outDir)
	if readErr != nil {
		t.Fatalf("failed to read output directory: %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no files written for invalid token, found %d entries", len(entries))
	}
}

func TestWriteLanguageResult_RejectsUnsafeCharacters(t *testing.T) {
	outDir := t.TempDir()
	w := NewLintWriter(outDir)

	err := w.WriteLanguageResult(lint.Language("go;rm -rf"), lint.NewResult())
	if err == nil {
		t.Fatal("expected error for unsafe language token, got nil")
	}

	if !strings.Contains(err.Error(), "only alphanumeric") {
		t.Fatalf("expected character validation error, got: %v", err)
	}
}
