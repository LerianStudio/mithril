//go:build integration

package ast

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestSchemaGolden_PythonExtractor_RoundTrips_Into_SemanticDiff verifies that
// py/ast_extractor.py emits JSON whose field names match the canonical
// SemanticDiff Go shape (internal/ast/types.go). It is a contract test for
// H44: if either side drifts, this test fails.
//
// The test invokes the real script so that field-name changes on the Python
// side, or JSON-tag changes on the Go side, break CI before a release.
func TestSchemaGolden_PythonExtractor_RoundTrips_Into_SemanticDiff(t *testing.T) {
	repoRoot := repoRootOrSkip(t)
	script := filepath.Join(repoRoot, "py", "ast_extractor.py")
	if _, err := os.Stat(script); err != nil {
		t.Skipf("Python extractor not found: %v", err)
	}

	before := filepath.Join(repoRoot, "testdata", "py", "before.py")
	after := filepath.Join(repoRoot, "testdata", "py", "after.py")
	requireFiles(t, before, after)

	out := runExtractor(t, "python3", script, "--base-dir", repoRoot, "--before", before, "--after", after)

	var diff SemanticDiff
	if err := json.Unmarshal(out, &diff); err != nil {
		t.Fatalf("Python output failed to unmarshal into SemanticDiff (field drift?): %v\npayload=%s", err, out)
	}

	assertCanonicalShape(t, diff, "python")
}

// TestSchemaGolden_TypeScriptExtractor_RoundTrips_Into_SemanticDiff mirrors
// the Python test above for ts/ast-extractor.ts. See H44.
func TestSchemaGolden_TypeScriptExtractor_RoundTrips_Into_SemanticDiff(t *testing.T) {
	repoRoot := repoRootOrSkip(t)
	tsDir := filepath.Join(repoRoot, "ts")
	dist := filepath.Join(tsDir, "dist", "ast-extractor.js")
	if _, err := os.Stat(dist); err != nil {
		t.Skipf("TypeScript extractor dist not built (run `cd ts && npm run build`): %v", err)
	}

	before := filepath.Join(repoRoot, "testdata", "ts", "before.ts")
	after := filepath.Join(repoRoot, "testdata", "ts", "after.ts")
	requireFiles(t, before, after)

	out := runExtractor(t, "node", dist, "--base-dir", repoRoot, "--before", before, "--after", after)

	var diff SemanticDiff
	if err := json.Unmarshal(out, &diff); err != nil {
		t.Fatalf("TypeScript output failed to unmarshal into SemanticDiff (field drift?): %v\npayload=%s", err, out)
	}

	assertCanonicalShape(t, diff, "typescript")
}

// assertCanonicalShape verifies the minimum contract that both extractor
// scripts must satisfy to be interchangeable consumers of SemanticDiff.
func assertCanonicalShape(t *testing.T, diff SemanticDiff, wantLang string) {
	t.Helper()

	if diff.Language != wantLang {
		t.Errorf("Language = %q, want %q", diff.Language, wantLang)
	}
	if diff.FilePath == "" {
		t.Error("FilePath is empty")
	}
	// At least one of functions/types/imports must be populated for the
	// fixtures we ship (before.* vs after.* differ by design).
	total := len(diff.Functions) + len(diff.Types) + len(diff.Imports)
	if total == 0 {
		t.Error("extractor produced no functions/types/imports; fixtures changed?")
	}

	// Each function entry must carry a name + change_type (the minimal
	// contract downstream consumers rely on).
	for i, fn := range diff.Functions {
		if fn.Name == "" {
			t.Errorf("Functions[%d].Name empty", i)
		}
		if fn.ChangeType == "" {
			t.Errorf("Functions[%d].ChangeType empty", i)
		}
	}
	for i, ty := range diff.Types {
		if ty.Name == "" {
			t.Errorf("Types[%d].Name empty", i)
		}
		if ty.ChangeType == "" {
			t.Errorf("Types[%d].ChangeType empty", i)
		}
	}
	for i, imp := range diff.Imports {
		if imp.Path == "" {
			t.Errorf("Imports[%d].Path empty", i)
		}
		if imp.ChangeType == "" {
			t.Errorf("Imports[%d].ChangeType empty", i)
		}
	}

	// Summary counts should be internally consistent with the functions
	// slice: the total of added+removed+modified must match how many
	// FunctionDiff entries exist (same for Types and Imports).
	funcSum := diff.Summary.FunctionsAdded + diff.Summary.FunctionsRemoved + diff.Summary.FunctionsModified
	if funcSum != len(diff.Functions) {
		t.Errorf("Summary function counts (%d) != len(Functions) (%d)", funcSum, len(diff.Functions))
	}
	typeSum := diff.Summary.TypesAdded + diff.Summary.TypesRemoved + diff.Summary.TypesModified
	if typeSum != len(diff.Types) {
		t.Errorf("Summary type counts (%d) != len(Types) (%d)", typeSum, len(diff.Types))
	}
	importSum := diff.Summary.ImportsAdded + diff.Summary.ImportsRemoved
	if importSum != len(diff.Imports) {
		t.Errorf("Summary import counts (%d) != len(Imports) (%d)", importSum, len(diff.Imports))
	}
}

func runExtractor(t *testing.T, command string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, command, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %v failed: %v\nstderr=%s", command, args, err, stderr.String())
	}
	return stdout.Bytes()
}

func repoRootOrSkip(t *testing.T) string {
	t.Helper()
	// This test file lives at <repo>/internal/ast/; walk up two levels.
	wd, err := os.Getwd()
	if err != nil {
		t.Skipf("cannot determine working directory: %v", err)
	}
	root := filepath.Join(wd, "..", "..")
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Skipf("cannot resolve repo root: %v", err)
	}
	return abs
}

func requireFiles(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("fixture not found: %s (%v)", p, err)
		}
	}
}
