package fileutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidatePath(t *testing.T) {
	workDir := t.TempDir()
	inside := filepath.Join(workDir, "sub", "file.json")
	if err := os.MkdirAll(filepath.Dir(inside), 0o755); err != nil {
		t.Fatalf("failed to create directories: %v", err)
	}
	if err := os.WriteFile(inside, []byte("{}"), 0o644); err != nil {
		t.Fatalf("failed to create inside file: %v", err)
	}

	if _, err := ValidatePath("sub/file.json", workDir); err != nil {
		t.Fatalf("expected relative inside path to validate: %v", err)
	}

	if _, err := ValidatePath(inside, workDir); err != nil {
		t.Fatalf("expected absolute inside path to validate: %v", err)
	}

	if _, err := ValidatePath("../escape.json", workDir); err == nil {
		t.Fatal("expected traversal path to be rejected")
	}

	if _, err := ValidatePath("", workDir); err == nil {
		t.Fatal("expected empty path to be rejected")
	}

	outside := filepath.Join(os.TempDir(), "outside.json")
	if _, err := ValidatePath(outside, workDir); err == nil {
		t.Fatal("expected absolute outside path to be rejected")
	}
}

func TestValidateDirectory(t *testing.T) {
	workDir := t.TempDir()
	dir := filepath.Join(workDir, "out")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}

	validated, err := ValidateDirectory(dir, workDir)
	if err != nil {
		t.Fatalf("expected directory validation to pass: %v", err)
	}
	if filepath.Clean(validated) != filepath.Clean(dir) {
		t.Fatalf("validated path mismatch: got %s, want %s", validated, dir)
	}

	filePath := filepath.Join(workDir, "file.txt")
	if err := os.WriteFile(filePath, []byte("x"), 0o644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	if _, err := ValidateDirectory(filePath, workDir); err == nil {
		t.Fatal("expected file path to fail directory validation")
	}
}

func TestValidatePath_WorkDirDotAllowsAbsolutePaths(t *testing.T) {
	outside := filepath.Join(os.TempDir(), "outside-dot.json")
	if _, err := ValidatePath(outside, "."); err != nil {
		t.Fatalf("expected absolute path to validate when workDir is '.': %v", err)
	}
}
