package ast

import (
	"path/filepath"
	"testing"
)

func TestDeriveBaseDir_SinglePathUsesExistingAncestor(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), "missing", "before.py")
	base := deriveBaseDir(missingPath)

	if base != filepath.Dir(filepath.Dir(missingPath)) {
		t.Fatalf("deriveBaseDir(%q) = %q, want %q", missingPath, base, filepath.Dir(filepath.Dir(missingPath)))
	}
}

func TestDeriveBaseDir_MultiplePathsUsesCommonAncestor(t *testing.T) {
	root := t.TempDir()
	left := filepath.Join(root, "a", "before.py")
	right := filepath.Join(root, "b", "after.py")

	base := deriveBaseDir(left, right)
	if base != root {
		t.Fatalf("deriveBaseDir(%q, %q) = %q, want %q", left, right, base, root)
	}
}
