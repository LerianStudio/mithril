package fileutil

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func TestValidatePath_EmptyWorkDirIsRejected(t *testing.T) {
	if _, err := ValidatePath("foo.json", ""); err == nil {
		t.Fatal("expected empty workDir to be rejected (relative path)")
	}
	outside := filepath.Join(os.TempDir(), "leak.json")
	if _, err := ValidatePath(outside, ""); err == nil {
		t.Fatal("expected empty workDir to be rejected (absolute path)")
	}
}

func TestWriteJSONFile_HappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")

	if err := WriteJSONFile(path, map[string]any{"x": 1, "y": "hi"}); err != nil {
		t.Fatalf("WriteJSONFile: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Error("expected trailing newline in output")
	}
	// Must be valid JSON.
	var back map[string]any
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	// Permission check
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("perm = %o, want 0o600", perm)
	}
}

func TestWriteJSONFile_RefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatalf("create target: %v", err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	err := WriteJSONFile(link, map[string]int{"a": 1})
	if err == nil {
		t.Fatal("expected symlink refusal")
	}
}

func TestWriteJSONFile_CreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "deep", "nest", "out.json")

	if err := WriteJSONFile(nested, map[string]int{"a": 1}); err != nil {
		t.Fatalf("WriteJSONFile: %v", err)
	}
	if _, err := os.Stat(nested); err != nil {
		t.Fatalf("output file missing: %v", err)
	}
}

func TestWriteJSONFile_CustomPerm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.json")

	if err := WriteJSONFile(path, []int{1, 2, 3}, WithPerm(0o640)); err != nil {
		t.Fatalf("WriteJSONFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("perm = %o, want 0o640", info.Mode().Perm())
	}
}

func TestWriteJSONFile_NoTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonl.json")

	if err := WriteJSONFile(path, 42, WithTrailingNewline(false)); err != nil {
		t.Fatalf("WriteJSONFile: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(data) == 0 || data[len(data)-1] == '\n' {
		t.Error("expected no trailing newline")
	}
}

func TestWriteJSONFile_AtomicCleansTmpOnMarshalError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cantmarshal.json")

	// channels can't be marshaled; json.MarshalIndent errors before tmp
	// creation, so no leftover tmp file should appear.
	err := WriteJSONFile(path, make(chan int))
	if err == nil {
		t.Fatal("expected marshal error")
	}
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatalf("failed to list temp dir: %v", readErr)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".writejson-") {
			t.Errorf("leftover tmp file %q after marshal error", entry.Name())
		}
	}
}

func TestWriteJSONFile_NonAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plain.json")

	if err := WriteJSONFile(path, "value", WithAtomicWrite(false)); err != nil {
		t.Fatalf("WriteJSONFile: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("output missing: %v", err)
	}
}
