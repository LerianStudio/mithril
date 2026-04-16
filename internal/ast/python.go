package ast

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"

	"github.com/lerianstudio/mithril/internal/procenv"
)

// PythonExtractor implements AST extraction for Python files
type PythonExtractor struct {
	pythonExecutable string
	scriptPath       string
}

// NewPythonExtractor creates a new Python AST extractor
func NewPythonExtractor(scriptDir string) *PythonExtractor {
	return &PythonExtractor{
		pythonExecutable: "python3",
		scriptPath:       filepath.Join(scriptDir, "py", "ast_extractor.py"),
	}
}

func (p *PythonExtractor) Language() string {
	return "python"
}

func (p *PythonExtractor) SupportedExtensions() []string {
	return []string{".py", ".pyi"}
}

func (p *PythonExtractor) ExtractDiff(ctx context.Context, beforePath, afterPath string) (*SemanticDiff, error) {
	before := beforePath
	if before == "" {
		before = `""`
	}
	after := afterPath
	if after == "" {
		after = `""`
	}

	args := []string{p.scriptPath, "--before", before, "--after", after, "--base-dir", deriveBaseDir(beforePath, afterPath)}

	output, err := procenv.RunHelper(ctx, "", p.pythonExecutable, args, 0)
	if err != nil {
		var tooLarge *procenv.OutputTooLargeError
		if errors.As(err, &tooLarge) {
			return nil, fmt.Errorf("python extractor output too large: %w", err)
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("python extractor failed: %s", string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("failed to run python extractor: %w", err)
	}

	var diff SemanticDiff
	if err := json.Unmarshal(output, &diff); err != nil {
		return nil, fmt.Errorf("failed to parse python extractor output: %w", err)
	}

	return &diff, nil
}
