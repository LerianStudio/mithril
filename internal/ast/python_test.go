package ast

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPythonExtractor_SupportedExtensions(t *testing.T) {
	extractor := NewPythonExtractor("")

	extensions := extractor.SupportedExtensions()

	assert.Len(t, extensions, 2)
	assert.Contains(t, extensions, ".py")
	assert.Contains(t, extensions, ".pyi")
}

func TestPythonExtractor_Language(t *testing.T) {
	extractor := NewPythonExtractor("")

	assert.Equal(t, "python", extractor.Language())
}

func TestPythonExtractor_NewExtractor(t *testing.T) {
	scriptDir := "/path/to/scripts"
	extractor := NewPythonExtractor(scriptDir)

	assert.Equal(t, "python3", extractor.pythonExecutable)
	assert.Equal(t, filepath.Join(scriptDir, "py", "ast_extractor.py"), extractor.scriptPath)
}

func TestPythonExtractor_ExtractDiff(t *testing.T) {
	// Skip if python3 is not available
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available, skipping Python extraction test")
	}

	// scriptDir is relative to this test file's location (internal/ast/)
	// The py directory is at ../../py from here
	scriptDir := filepath.Join("..", "..")
	extractor := NewPythonExtractor(scriptDir)

	beforePath := filepath.Join("..", "..", "testdata", "py", "before.py")
	afterPath := filepath.Join("..", "..", "testdata", "py", "after.py")

	diff, err := extractor.ExtractDiff(context.Background(), beforePath, afterPath)
	require.NoError(t, err, "ExtractDiff should succeed")

	// Verify language
	assert.Equal(t, "python", diff.Language)

	// Verify SemanticDiff structure fields exist
	assert.NotNil(t, diff.Functions, "Functions should not be nil")
	assert.NotNil(t, diff.Types, "Types should not be nil")
	assert.NotNil(t, diff.Imports, "Imports should not be nil")

	// Verify function changes
	funcChanges := make(map[string]ChangeType)
	for _, f := range diff.Functions {
		funcChanges[f.Name] = f.ChangeType
	}

	// greet should be modified (added parameter)
	ct, ok := funcChanges["greet"]
	require.True(t, ok, "greet should exist in function changes")
	assert.Equal(t, ChangeModified, ct, "greet should be modified")

	// format_name should be removed
	ct, ok = funcChanges["format_name"]
	require.True(t, ok, "format_name should exist in function changes")
	assert.Equal(t, ChangeRemoved, ct, "format_name should be removed")

	// validate_email should be added
	ct, ok = funcChanges["validate_email"]
	require.True(t, ok, "validate_email should exist in function changes")
	assert.Equal(t, ChangeAdded, ct, "validate_email should be added")

	// Verify type/class changes
	typeChanges := make(map[string]ChangeType)
	for _, ty := range diff.Types {
		typeChanges[ty.Name] = ty.ChangeType
	}

	// User class should be modified (fields added)
	ct, ok = typeChanges["User"]
	require.True(t, ok, "User should exist in type changes")
	assert.Equal(t, ChangeModified, ct, "User should be modified")

	// Config class should be added
	ct, ok = typeChanges["Config"]
	require.True(t, ok, "Config should exist in type changes")
	assert.Equal(t, ChangeAdded, ct, "Config should be added")

	// Verify import changes
	importChanges := make(map[string]ChangeType)
	for _, imp := range diff.Imports {
		importChanges[imp.Path] = imp.ChangeType
	}

	// os should be removed
	ct, ok = importChanges["os"]
	require.True(t, ok, "os import should exist in import changes")
	assert.Equal(t, ChangeRemoved, ct, "os should be removed")

	// logging should be added
	ct, ok = importChanges["logging"]
	require.True(t, ok, "logging import should exist in import changes")
	assert.Equal(t, ChangeAdded, ct, "logging should be added")

	// Verify summary has reasonable values
	assert.GreaterOrEqual(t, diff.Summary.FunctionsAdded, 0, "FunctionsAdded should be >= 0")
	assert.GreaterOrEqual(t, diff.Summary.FunctionsRemoved, 0, "FunctionsRemoved should be >= 0")
	assert.GreaterOrEqual(t, diff.Summary.TypesAdded, 0, "TypesAdded should be >= 0")
}

func TestPythonExtractor_NewFile(t *testing.T) {
	// Skip if python3 is not available
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available, skipping Python extraction test")
	}

	scriptDir := filepath.Join("..", "..")
	extractor := NewPythonExtractor(scriptDir)

	afterPath := filepath.Join("..", "..", "testdata", "py", "after.py")

	diff, err := extractor.ExtractDiff(context.Background(), "", afterPath)
	require.NoError(t, err, "ExtractDiff should succeed for new file")

	// All functions should be added
	for _, f := range diff.Functions {
		assert.Equal(t, ChangeAdded, f.ChangeType, "function %s should be added", f.Name)
	}

	// All types should be added
	for _, ty := range diff.Types {
		assert.Equal(t, ChangeAdded, ty.ChangeType, "type %s should be added", ty.Name)
	}
}

func TestPythonExtractor_DeletedFile(t *testing.T) {
	// Skip if python3 is not available
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available, skipping Python extraction test")
	}

	scriptDir := filepath.Join("..", "..")
	extractor := NewPythonExtractor(scriptDir)

	beforePath := filepath.Join("..", "..", "testdata", "py", "before.py")

	diff, err := extractor.ExtractDiff(context.Background(), beforePath, "")
	require.NoError(t, err, "ExtractDiff should succeed for deleted file")

	// All functions should be removed
	for _, f := range diff.Functions {
		assert.Equal(t, ChangeRemoved, f.ChangeType, "function %s should be removed", f.Name)
	}

	// All types should be removed
	for _, ty := range diff.Types {
		assert.Equal(t, ChangeRemoved, ty.ChangeType, "type %s should be removed", ty.Name)
	}
}

func TestPythonExtractor_NonexistentFileTreatedAsEmpty(t *testing.T) {
	// Skip if python3 is not available
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available, skipping Python extraction test")
	}

	scriptDir := filepath.Join("..", "..")
	extractor := NewPythonExtractor(scriptDir)

	// Nonexistent files are treated as empty (design decision for diff tools)
	// This allows comparing new files (empty before) and deleted files (empty after)
	diff, err := extractor.ExtractDiff(context.Background(), "/nonexistent/file.py", "")
	require.NoError(t, err, "nonexistent file should be treated as empty, not error")

	// Should return an empty diff since both sides are effectively empty
	assert.Empty(t, diff.Functions, "no functions expected from empty diff")
	assert.Empty(t, diff.Types, "no types expected from empty diff")
}

func TestPythonExtractor_InvalidScript(t *testing.T) {
	extractor := NewPythonExtractor("/nonexistent/path")

	_, err := extractor.ExtractDiff(context.Background(), "test.py", "")

	require.Error(t, err, "expected error for nonexistent script")
}

func TestPythonExtractor_ParamOnlyChangeDoesNotFlagImplementation(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available, skipping Python extraction test")
	}

	scriptDir := filepath.Join("..", "..")
	extractor := NewPythonExtractor(scriptDir)
	tempDir := t.TempDir()

	beforePath := filepath.Join(tempDir, "before.py")
	afterPath := filepath.Join(tempDir, "after.py")

	before := "def greet(name: str) -> str:\n    return f\"Hello, {name}!\"\n"
	after := "def greet(name: str, greeting: str = \"Hello\") -> str:\n    return f\"Hello, {name}!\"\n"

	require.NoError(t, os.WriteFile(beforePath, []byte(before), 0o644))
	require.NoError(t, os.WriteFile(afterPath, []byte(after), 0o644))

	diff, err := extractor.ExtractDiff(context.Background(), beforePath, afterPath)
	require.NoError(t, err)

	var greetDiff *FunctionDiff
	for i := range diff.Functions {
		if diff.Functions[i].Name == "greet" {
			greetDiff = &diff.Functions[i]
			break
		}
	}
	require.NotNil(t, greetDiff, "expected greet function diff")
	assert.Equal(t, ChangeModified, greetDiff.ChangeType)
	assert.Contains(t, greetDiff.BodyDiff, "parameters changed")
	assert.NotContains(t, greetDiff.BodyDiff, "implementation changed")
}

func TestPythonExtractor_ImportAliasModificationDetected(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available, skipping Python extraction test")
	}

	scriptDir := filepath.Join("..", "..")
	extractor := NewPythonExtractor(scriptDir)
	tempDir := t.TempDir()

	beforePath := filepath.Join(tempDir, "before.py")
	afterPath := filepath.Join(tempDir, "after.py")

	require.NoError(t, os.WriteFile(beforePath, []byte("import numpy as np\n"), 0o644))
	require.NoError(t, os.WriteFile(afterPath, []byte("import numpy as npy\n"), 0o644))

	diff, err := extractor.ExtractDiff(context.Background(), beforePath, afterPath)
	require.NoError(t, err)

	var aliasDiff *ImportDiff
	for i := range diff.Imports {
		if diff.Imports[i].Path == "numpy" {
			aliasDiff = &diff.Imports[i]
			break
		}
	}
	require.NotNil(t, aliasDiff, "expected numpy import diff")
	assert.Equal(t, ChangeModified, aliasDiff.ChangeType)
	assert.Equal(t, "npy", aliasDiff.Alias)
}

func TestPythonExtractor_VariableDiffDetected(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available, skipping Python extraction test")
	}

	scriptDir := filepath.Join("..", "..")
	extractor := NewPythonExtractor(scriptDir)
	tempDir := t.TempDir()

	beforePath := filepath.Join(tempDir, "before.py")
	afterPath := filepath.Join(tempDir, "after.py")

	before := "CONFIG = 1\nname = \"old\"\n"
	after := "CONFIG = 2\nnew_value = \"new\"\n"

	require.NoError(t, os.WriteFile(beforePath, []byte(before), 0o644))
	require.NoError(t, os.WriteFile(afterPath, []byte(after), 0o644))

	diff, err := extractor.ExtractDiff(context.Background(), beforePath, afterPath)
	require.NoError(t, err)

	var changes = map[string]ChangeType{}
	for _, v := range diff.Variables {
		changes[v.Name] = v.ChangeType
	}

	assert.Equal(t, ChangeModified, changes["CONFIG"])
	assert.Equal(t, ChangeRemoved, changes["name"])
	assert.Equal(t, ChangeAdded, changes["new_value"])
	assert.Equal(t, 1, diff.Summary.VariablesAdded)
	assert.Equal(t, 1, diff.Summary.VariablesRemoved)
	assert.Equal(t, 1, diff.Summary.VariablesModified)
}
