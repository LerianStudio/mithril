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

func TestTypeScriptExtractor_SupportedExtensions(t *testing.T) {
	extractor := NewTypeScriptExtractor("")

	extensions := extractor.SupportedExtensions()

	assert.Len(t, extensions, 5)
	assert.Contains(t, extensions, ".ts")
	assert.Contains(t, extensions, ".tsx")
	assert.Contains(t, extensions, ".js")
	assert.Contains(t, extensions, ".jsx")
	assert.Contains(t, extensions, ".d.ts")
}

func TestTypeScriptExtractor_Language(t *testing.T) {
	extractor := NewTypeScriptExtractor("")

	assert.Equal(t, "typescript", extractor.Language())
}

func TestTypeScriptExtractor_NewExtractor(t *testing.T) {
	scriptDir := "/path/to/scripts"
	extractor := NewTypeScriptExtractor(scriptDir)

	assert.Equal(t, "node", extractor.nodeExecutable)
	assert.Equal(t, findTypeScriptASTExtractor(scriptDir), extractor.scriptPath)
}

func TestTypeScriptExtractor_ExtractDiff(t *testing.T) {
	// Skip if node is not available
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available, skipping TypeScript extraction test")
	}
	skipIfTypeScriptModuleUnavailable(t)

	// scriptDir is relative to this test file's location (internal/ast/)
	// The ts/dist directory is at ../../ts/dist from here
	scriptDir := filepath.Join("..", "..")
	extractor := NewTypeScriptExtractor(scriptDir)

	beforePath := filepath.Join("..", "..", "testdata", "ts", "before.ts")
	afterPath := filepath.Join("..", "..", "testdata", "ts", "after.ts")

	diff, err := extractor.ExtractDiff(context.Background(), beforePath, afterPath)
	require.NoError(t, err, "ExtractDiff should succeed")

	// Verify language
	assert.Equal(t, "typescript", diff.Language)

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

	// formatName should be removed
	ct, ok = funcChanges["formatName"]
	require.True(t, ok, "formatName should exist in function changes")
	assert.Equal(t, ChangeRemoved, ct, "formatName should be removed")

	// validateEmail should be added
	ct, ok = funcChanges["validateEmail"]
	require.True(t, ok, "validateEmail should exist in function changes")
	assert.Equal(t, ChangeAdded, ct, "validateEmail should be added")

	// Verify type changes
	typeChanges := make(map[string]ChangeType)
	for _, ty := range diff.Types {
		typeChanges[ty.Name] = ty.ChangeType
	}

	// User interface should be modified (fields added)
	ct, ok = typeChanges["User"]
	require.True(t, ok, "User should exist in type changes")
	assert.Equal(t, ChangeModified, ct, "User should be modified")

	// Config interface should be added
	ct, ok = typeChanges["Config"]
	require.True(t, ok, "Config should exist in type changes")
	assert.Equal(t, ChangeAdded, ct, "Config should be added")

	// Verify import changes
	importChanges := make(map[string]ChangeType)
	for _, imp := range diff.Imports {
		importChanges[imp.Path] = imp.ChangeType
	}

	// axios should be removed
	ct, ok = importChanges["axios"]
	require.True(t, ok, "axios import should exist in import changes")
	assert.Equal(t, ChangeRemoved, ct, "axios should be removed")

	// ./api should be added
	ct, ok = importChanges["./api"]
	require.True(t, ok, "./api import should exist in import changes")
	assert.Equal(t, ChangeAdded, ct, "./api should be added")

	// Verify summary has reasonable values
	assert.GreaterOrEqual(t, diff.Summary.FunctionsAdded, 0, "FunctionsAdded should be >= 0")
	assert.GreaterOrEqual(t, diff.Summary.FunctionsRemoved, 0, "FunctionsRemoved should be >= 0")
	assert.GreaterOrEqual(t, diff.Summary.TypesAdded, 0, "TypesAdded should be >= 0")
}

func TestTypeScriptExtractor_NewFile(t *testing.T) {
	// Skip if node is not available
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available, skipping TypeScript extraction test")
	}
	skipIfTypeScriptModuleUnavailable(t)

	scriptDir := filepath.Join("..", "..")
	extractor := NewTypeScriptExtractor(scriptDir)

	afterPath := filepath.Join("..", "..", "testdata", "ts", "after.ts")

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

func TestTypeScriptExtractor_DeletedFile(t *testing.T) {
	// Skip if node is not available
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available, skipping TypeScript extraction test")
	}
	skipIfTypeScriptModuleUnavailable(t)

	scriptDir := filepath.Join("..", "..")
	extractor := NewTypeScriptExtractor(scriptDir)

	beforePath := filepath.Join("..", "..", "testdata", "ts", "before.ts")

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

func TestTypeScriptExtractor_NonexistentFileTreatedAsEmpty(t *testing.T) {
	// Skip if node is not available
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available, skipping TypeScript extraction test")
	}
	skipIfTypeScriptModuleUnavailable(t)

	scriptDir := filepath.Join("..", "..")
	extractor := NewTypeScriptExtractor(scriptDir)

	// Nonexistent files are treated as empty (design decision for diff tools)
	// This allows comparing new files (empty before) and deleted files (empty after)
	diff, err := extractor.ExtractDiff(context.Background(), "/nonexistent/file.ts", "")
	require.NoError(t, err, "nonexistent file should be treated as empty, not error")

	// Should return an empty diff since both sides are effectively empty
	assert.Empty(t, diff.Functions, "no functions expected from empty diff")
	assert.Empty(t, diff.Types, "no types expected from empty diff")
}

func TestTypeScriptExtractor_InvalidScript(t *testing.T) {
	extractor := NewTypeScriptExtractor("/nonexistent/path")

	_, err := extractor.ExtractDiff(context.Background(), "test.ts", "")

	require.Error(t, err, "expected error for nonexistent script")
}

func skipIfTypeScriptModuleUnavailable(t *testing.T) {
	t.Helper()
	check := exec.Command("node", "-e", "require('typescript')")
	if err := check.Run(); err != nil {
		t.Skip("typescript module not available, skipping TypeScript extraction test")
	}
}

func TestTypeScriptExtractor_ImportAliasModificationDetected(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available, skipping TypeScript extraction test")
	}
	skipIfTypeScriptModuleUnavailable(t)

	scriptDir := filepath.Join("..", "..")
	extractor := NewTypeScriptExtractor(scriptDir)
	tempDir := t.TempDir()

	beforePath := filepath.Join(tempDir, "before.ts")
	afterPath := filepath.Join(tempDir, "after.ts")

	before := "import axios from 'axios'\nexport const x = 1\n"
	after := "import httpClient from 'axios'\nexport const x = 1\n"

	require.NoError(t, os.WriteFile(beforePath, []byte(before), 0o644))
	require.NoError(t, os.WriteFile(afterPath, []byte(after), 0o644))

	diff, err := extractor.ExtractDiff(context.Background(), beforePath, afterPath)
	require.NoError(t, err)

	var aliasDiff *ImportDiff
	for i := range diff.Imports {
		if diff.Imports[i].Path == "axios" {
			aliasDiff = &diff.Imports[i]
			break
		}
	}
	require.NotNil(t, aliasDiff, "expected axios import diff")
	assert.Equal(t, ChangeModified, aliasDiff.ChangeType)
	assert.Equal(t, "httpClient", aliasDiff.Alias)
}

func TestTypeScriptExtractor_VariableDiffDetected(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available, skipping TypeScript extraction test")
	}
	skipIfTypeScriptModuleUnavailable(t)

	scriptDir := filepath.Join("..", "..")
	extractor := NewTypeScriptExtractor(scriptDir)
	tempDir := t.TempDir()

	beforePath := filepath.Join(tempDir, "before.ts")
	afterPath := filepath.Join(tempDir, "after.ts")

	before := "const API_VERSION = 1\nlet name = 'old'\n"
	after := "const API_VERSION = 2\nconst createdAt = Date.now()\n"

	require.NoError(t, os.WriteFile(beforePath, []byte(before), 0o644))
	require.NoError(t, os.WriteFile(afterPath, []byte(after), 0o644))

	diff, err := extractor.ExtractDiff(context.Background(), beforePath, afterPath)
	require.NoError(t, err)

	changes := make(map[string]ChangeType)
	for _, v := range diff.Variables {
		changes[v.Name] = v.ChangeType
	}

	assert.Equal(t, ChangeModified, changes["API_VERSION"])
	assert.Equal(t, ChangeRemoved, changes["name"])
	assert.Equal(t, ChangeAdded, changes["createdAt"])
	assert.Equal(t, 1, diff.Summary.VariablesAdded)
	assert.Equal(t, 1, diff.Summary.VariablesRemoved)
	assert.Equal(t, 1, diff.Summary.VariablesModified)
}
