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
	for _, p := range absPaths[1:] {
		for !isPathWithinBase(p, baseDir) {
			parent := filepath.Dir(baseDir)
			if parent == baseDir {
				break
			}
			baseDir = parent
		}
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
