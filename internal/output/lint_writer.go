// Package output handles writing analysis results to files.
package output

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/lerianstudio/mithril/internal/fileutil"
	"github.com/lerianstudio/mithril/internal/lint"
)

var safeLanguageTokenPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// LintWriter handles writing lint analysis results.
type LintWriter struct {
	outputDir string
}

// NewLintWriter creates a new lint output writer.
func NewLintWriter(outputDir string) *LintWriter {
	return &LintWriter{
		outputDir: outputDir,
	}
}

// EnsureDir creates the output directory if it doesn't exist.
func (w *LintWriter) EnsureDir() error {
	return os.MkdirAll(w.outputDir, 0o700)
}

// WriteResult writes the analysis result to static-analysis.json.
func (w *LintWriter) WriteResult(result *lint.Result) error {
	return w.writeJSON("static-analysis.json", result)
}

// WriteLanguageResult writes a language-specific result file.
func (w *LintWriter) WriteLanguageResult(lang lint.Language, result *lint.Result) error {
	token, err := sanitizeLanguageToken(string(lang))
	if err != nil {
		return err
	}

	filename := fmt.Sprintf("%s-lint.json", token)
	return w.writeJSON(filename, result)
}

func sanitizeLanguageToken(raw string) (string, error) {
	base := filepath.Base(raw)
	if base != raw {
		return "", fmt.Errorf("invalid language token %q: path separators are not allowed", raw)
	}

	if !safeLanguageTokenPattern.MatchString(base) {
		return "", fmt.Errorf("invalid language token %q: only alphanumeric, dash, underscore allowed", raw)
	}

	return base, nil
}

// writeJSON writes data as formatted JSON to a file.
func (w *LintWriter) writeJSON(filename string, data any) error {
	path := filepath.Join(w.outputDir, filename)
	return fileutil.WriteJSONFile(path, data)
}

// DefaultOutputDir returns the default output directory.
func DefaultOutputDir(projectDir string) string {
	return filepath.Join(projectDir, ".ring", "codereview")
}
