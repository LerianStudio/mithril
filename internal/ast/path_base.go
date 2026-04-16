package ast

import (
	"os"
	"path/filepath"
	"strings"
)

func deriveBaseDir(paths ...string) string {
	absPaths := make([]string, 0, len(paths))
	for _, p := range paths {
		if p == "" {
			continue
		}
		absPath, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		absPaths = append(absPaths, absPath)
	}

	if len(absPaths) == 0 {
		return "."
	}

	baseDir := filepath.Dir(absPaths[0])
	climbedToRoot := false
	for _, p := range absPaths[1:] {
		for !isPathWithinBase(p, baseDir) {
			parent := filepath.Dir(baseDir)
			if parent == baseDir {
				climbedToRoot = true
				break
			}
			baseDir = parent
		}
	}

	// If the multi-path LCA climb reached filesystem root, the inputs are
	// genuinely disjoint and a root-wide base is not a meaningful sandbox.
	// Fall back to cwd so
	// downstream validators still enforce some containment.
	if climbedToRoot && isFilesystemRoot(baseDir) {
		if cwd, err := os.Getwd(); err == nil {
			return cwd
		}
		return "."
	}

	for {
		info, err := os.Stat(baseDir)
		if err == nil && info.IsDir() {
			return baseDir
		}

		parent := filepath.Dir(baseDir)
		if parent == baseDir {
			return baseDir
		}
		baseDir = parent
	}
}

func isFilesystemRoot(p string) bool {
	parent := filepath.Dir(p)
	return parent == p
}

func isPathWithinBase(path, base string) bool {
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return false
	}

	if rel == "." {
		return true
	}

	if rel == ".." {
		return false
	}

	return !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
