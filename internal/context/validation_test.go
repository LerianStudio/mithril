package context

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidatePath(t *testing.T) {
	inputDir := t.TempDir()

	if err := validatePath(inputDir, true); err != nil {
		t.Fatalf("expected existing directory to validate: %v", err)
	}

	if err := validatePath("../outside", false); err == nil {
		t.Fatal("expected traversal path to fail validation")
	}

	absPath := filepath.Join(os.TempDir(), "outside-validation-dir")
	if err := validatePath(absPath, false); err != nil {
		t.Fatalf("expected absolute path to validate when existence is not required: %v", err)
	}
}

func TestNewCompilerWithValidation(t *testing.T) {
	inputDir := t.TempDir()
	outputDir := filepath.Join(inputDir, "out")

	compiler, err := NewCompilerWithValidation(inputDir, outputDir)
	if err != nil {
		t.Fatalf("expected valid compiler initialization: %v", err)
	}
	if compiler == nil {
		t.Fatal("expected compiler instance")
	}

	if _, err := NewCompilerWithValidation(filepath.Join(inputDir, "missing"), outputDir); err == nil {
		t.Fatal("expected missing input directory to fail")
	}
}
