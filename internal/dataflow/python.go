// Package dataflow provides data flow analysis for security review.
package dataflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/lerianstudio/mithril/internal/procenv"
)

// ScriptAnalyzer implements data flow analysis for Python and TypeScript by
// delegating to the shared py/data_flow.py helper. The same struct drives
// both languages; the language field selects which regex pattern set runs
// inside the helper.
type ScriptAnalyzer struct {
	scriptPath string
	language   string
}

// PythonAnalyzer is kept as an alias for backward compatibility with
// callers that imported the original type name. New code should use
// ScriptAnalyzer.
type PythonAnalyzer = ScriptAnalyzer

// NewPythonAnalyzer creates a new analyzer for Python files.
func NewPythonAnalyzer(scriptDir string) *ScriptAnalyzer {
	return &ScriptAnalyzer{
		scriptPath: filepath.Join(scriptDir, "py", "data_flow.py"),
		language:   "python",
	}
}

// NewTypeScriptAnalyzer creates a new analyzer for TypeScript/JavaScript
// files. It returns a *ScriptAnalyzer configured for TypeScript; the same
// underlying struct drives both languages.
func NewTypeScriptAnalyzer(scriptDir string) *ScriptAnalyzer {
	return &ScriptAnalyzer{
		scriptPath: filepath.Join(scriptDir, "py", "data_flow.py"),
		language:   "typescript",
	}
}

// Language returns the analyzer's target language.
func (p *ScriptAnalyzer) Language() string {
	return p.language
}

// filterFiles filters the given files to only include those matching the analyzer's language.
func (p *ScriptAnalyzer) filterFiles(files []string) []string {
	var filtered []string

	for _, file := range files {
		ext := strings.ToLower(filepath.Ext(file))
		switch p.language {
		case "python":
			if ext == ".py" {
				filtered = append(filtered, file)
			}
		case "typescript":
			if ext == ".ts" || ext == ".tsx" || ext == ".js" || ext == ".jsx" {
				filtered = append(filtered, file)
			}
		}
	}

	return filtered
}

// runScript executes the Python data flow analysis script and parses its output.
func (p *ScriptAnalyzer) runScript(files []string) (*FlowAnalysis, error) {
	filteredFiles := p.filterFiles(files)
	if len(filteredFiles) == 0 {
		return &FlowAnalysis{
			Language:   p.language,
			Sources:    []Source{},
			Sinks:      []Sink{},
			Flows:      []Flow{},
			NilSources: []NilSource{},
			Statistics: Stats{},
		}, nil
	}

	manifest, err := os.CreateTemp("", "dataflow-files-*.txt")
	if err != nil {
		return nil, fmt.Errorf("creating file manifest: %w", err)
	}
	manifestPath := manifest.Name()
	defer func() {
		_ = manifest.Close()
		_ = os.Remove(manifestPath)
	}()

	if _, err := manifest.WriteString(strings.Join(filteredFiles, "\n")); err != nil {
		return nil, fmt.Errorf("writing file manifest: %w", err)
	}
	if err := manifest.Close(); err != nil {
		return nil, fmt.Errorf("closing file manifest: %w", err)
	}

	// Build command arguments: python3 script.py <language> --files-from <manifest>
	args := []string{p.scriptPath, p.language, "--files-from", manifestPath}

	output, err := procenv.RunHelper(context.Background(), "", "python3", args, 0)
	if err != nil {
		var tooLarge *procenv.OutputTooLargeError
		if errors.As(err, &tooLarge) {
			return nil, fmt.Errorf("dataflow script output too large: %w", err)
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			stderrStr := strings.TrimSpace(string(exitErr.Stderr))
			if stderrStr != "" {
				return nil, fmt.Errorf("script execution failed: %w: %s", err, stderrStr)
			}
		}
		return nil, fmt.Errorf("script execution failed: %w", err)
	}

	var analysis FlowAnalysis
	if err := json.Unmarshal(output, &analysis); err != nil {
		return nil, fmt.Errorf("parsing script output: %w", err)
	}

	return &analysis, nil
}

// DetectSources scans files for untrusted data sources.
func (p *ScriptAnalyzer) DetectSources(files []string) ([]Source, error) {
	analysis, err := p.runScript(files)
	if err != nil {
		return nil, fmt.Errorf("detecting sources: %w", err)
	}
	return analysis.Sources, nil
}

// DetectSinks scans files for sensitive data sinks.
func (p *ScriptAnalyzer) DetectSinks(files []string) ([]Sink, error) {
	analysis, err := p.runScript(files)
	if err != nil {
		return nil, fmt.Errorf("detecting sinks: %w", err)
	}
	return analysis.Sinks, nil
}

// TrackFlows traces data paths from sources to sinks.
// Note: This method re-runs the full analysis since the Python script
// performs integrated analysis. The sources and sinks parameters are
// ignored as the script determines them internally.
func (p *ScriptAnalyzer) TrackFlows(sources []Source, sinks []Sink, files []string) ([]Flow, error) {
	analysis, err := p.runScript(files)
	if err != nil {
		return nil, fmt.Errorf("tracking flows: %w", err)
	}
	return analysis.Flows, nil
}

// DetectNilSources identifies variables that may be nil/null/undefined.
func (p *ScriptAnalyzer) DetectNilSources(files []string) ([]NilSource, error) {
	analysis, err := p.runScript(files)
	if err != nil {
		return nil, fmt.Errorf("detecting nil sources: %w", err)
	}
	return analysis.NilSources, nil
}

// Analyze performs complete data flow analysis on the given files.
func (p *ScriptAnalyzer) Analyze(files []string) (*FlowAnalysis, error) {
	return p.runScript(files)
}
