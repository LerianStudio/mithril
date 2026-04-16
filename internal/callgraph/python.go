package callgraph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/lerianstudio/mithril/internal/fileutil"
)

// Resource protection limits for Python analysis.
const (
	pyMaxModifiedFunctions = 500 // Maximum number of modified functions to analyze
	pyDefaultTimeBudgetSec = 120 // Default time budget when not specified
)

// PythonAnalyzer implements call graph analysis for Python code.
type PythonAnalyzer struct {
	workDir         string
	runHelperFn     func(ctx context.Context, files []string, modifiedFuncs []ModifiedFunction) (*pyHelperOutput, error)
	runFallbackFn   func(ctx context.Context, modifiedFuncs []ModifiedFunction, result *CallGraphResult) (*CallGraphResult, error)
	processHelperFn func(helper *pyHelperOutput, modifiedFuncs []ModifiedFunction, result *CallGraphResult) (*CallGraphResult, error)
}

// NewPythonAnalyzer creates a new Python call graph analyzer.
// workDir is the root directory for module resolution.
func NewPythonAnalyzer(workDir string) *PythonAnalyzer {
	return &PythonAnalyzer{
		workDir:         workDir,
		runHelperFn:     nil,
		runFallbackFn:   nil,
		processHelperFn: nil,
	}
}

// sanitizeFilePaths validates file paths to prevent command injection and path traversal.
func (p *PythonAnalyzer) sanitizeFilePaths(files []string) ([]string, error) {
	return sanitizeHelperFilePaths(p.workDir, files)
}

// validPythonIdentifier is a regex pattern for valid Python identifiers.
// Matches: identifier or module.identifier or Class.method patterns.
var validPythonIdentifier = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)*$`)

// sanitizeFunctionNames validates function names to prevent command injection.
func (p *PythonAnalyzer) sanitizeFunctionNames(names []string) ([]string, error) {
	var sanitized []string
	for _, name := range names {
		// Reject names starting with dash (command injection)
		if strings.HasPrefix(name, "-") {
			return nil, fmt.Errorf("invalid function name (starts with dash): %s", name)
		}
		// Validate against Python identifier pattern
		if !validPythonIdentifier.MatchString(name) {
			return nil, fmt.Errorf("invalid function name (not a valid identifier): %s", name)
		}
		sanitized = append(sanitized, name)
	}
	return sanitized, nil
}

// pyHelperOutput represents the output from the Python call-graph helper.
type pyHelperOutput struct {
	Functions []pyHelperFunction `json:"functions"`
	Error     string             `json:"error,omitempty"`
}

// pyHelperFunction represents function-level call information from the helper.
type pyHelperFunction struct {
	Name      string           `json:"name"`
	File      string           `json:"file"`
	Line      int              `json:"line"`
	EndLine   int              `json:"end_line"`
	CallSites []pyHelperCall   `json:"call_sites"`
	CalledBy  []pyHelperCaller `json:"called_by,omitempty"`
}

// pyHelperCall represents a call made from a function.
type pyHelperCall struct {
	Target   string `json:"target"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	IsMethod bool   `json:"is_method"`
}

// pyHelperCaller represents a caller of a function (when using --functions flag).
type pyHelperCaller struct {
	Function string `json:"function"`
	File     string `json:"file"`
	Line     int    `json:"line"`
}

// Analyze implements the Analyzer interface for Python code.
func (p *PythonAnalyzer) Analyze(modifiedFuncs []ModifiedFunction, timeBudgetSec int) (*CallGraphResult, error) {
	result := &CallGraphResult{
		Language:          "python",
		ModifiedFunctions: make([]FunctionCallGraph, 0, len(modifiedFuncs)),
		Warnings:          []string{},
		ImpactAnalysis: ImpactAnalysis{
			AffectedPackages: p.getAffectedPackages(modifiedFuncs),
		},
	}

	if len(modifiedFuncs) == 0 {
		return result, nil
	}

	// Input validation: truncate if exceeding limit
	if len(modifiedFuncs) > pyMaxModifiedFunctions {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Truncated modified functions from %d to %d", len(modifiedFuncs), pyMaxModifiedFunctions))
		modifiedFuncs = modifiedFuncs[:pyMaxModifiedFunctions]
		result.PartialResults = true
	}

	// Apply default time budget if not specified
	if timeBudgetSec <= 0 {
		timeBudgetSec = pyDefaultTimeBudgetSec
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeBudgetSec)*time.Second)
	defer cancel()

	// Collect unique files to analyze
	files := p.collectUniqueFiles(modifiedFuncs)

	// Try to use the custom Python helper for detailed analysis
	runHelper := p.runHelperFn
	if runHelper == nil {
		runHelper = p.runCallGraphPy
	}
	runFallback := p.runFallbackFn
	if runFallback == nil {
		runFallback = p.runPyan3
	}
	processHelper := p.processHelperFn
	if processHelper == nil {
		processHelper = p.processHelperResults
	}

	helperResult, helperErr := runHelper(ctx, files, modifiedFuncs)
	if helperErr != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Python helper unavailable: %v", helperErr))
		// Fall back to pyan3
		return runFallback(ctx, modifiedFuncs, result)
	}

	// Python dynamic dispatch patterns (getattr, super(), monkey patching,
	// decorators rewriting callables) cannot be resolved by static AST
	// analysis; surface a single advisory warning so downstream consumers
	// know the graph is a lower bound (see H15).
	result.Warnings = append(result.Warnings,
		"Python dynamic dispatch (getattr, super(), monkey-patching, dynamically-assigned decorators) is not tracked; call graph is a lower bound.")

	// Process helper results
	return processHelper(helperResult, modifiedFuncs, result)
}

// getAffectedPackages extracts unique package paths from modified functions.
func (p *PythonAnalyzer) getAffectedPackages(funcs []ModifiedFunction) []string {
	return affectedPackages(funcs)
}

// collectUniqueFiles returns unique file paths from modified functions.
func (p *PythonAnalyzer) collectUniqueFiles(funcs []ModifiedFunction) []string {
	return collectUniqueFiles(funcs)
}

func (p *PythonAnalyzer) runPythonHelperCommand(ctx context.Context, pythonBinary string, args []string) ([]byte, error) {
	return runHelperCommand(ctx, p.workDir, pythonBinary, args)
}

// runCallGraphPy uses the custom Python call_graph.py script for detailed analysis.
func (p *PythonAnalyzer) runCallGraphPy(ctx context.Context, files []string, modifiedFuncs []ModifiedFunction) (*pyHelperOutput, error) {
	if len(files) == 0 {
		return &pyHelperOutput{}, nil
	}

	// Sanitize file paths to prevent command injection
	sanitizedFiles, err := p.sanitizeFilePaths(files)
	if err != nil {
		return nil, fmt.Errorf("file path validation failed: %w", err)
	}
	files = sanitizedFiles

	// Build function filter for --functions flag
	var funcNames []string
	for _, fn := range modifiedFuncs {
		funcNames = append(funcNames, fn.Name)
	}

	// Sanitize function names to prevent command injection
	if len(funcNames) > 0 {
		sanitizedFuncs, err := p.sanitizeFunctionNames(funcNames)
		if err != nil {
			return nil, fmt.Errorf("function name validation failed: %w", err)
		}
		funcNames = sanitizedFuncs
	}

	// Locate the helper script
	helperPath := p.findHelperScript()
	if helperPath == "" {
		return nil, fmt.Errorf("call_graph.py helper script not found")
	}
	validatedHelper, err := fileutil.ValidatePath(helperPath, ".")
	if err != nil {
		return nil, fmt.Errorf("helper script path invalid: %w", err)
	}
	helperPath = validatedHelper

	// Build command arguments
	args := []string{helperPath}
	args = append(args, files...)
	if len(funcNames) > 0 {
		args = append(args, "--functions", strings.Join(funcNames, ","))
	}

	// Try python3 first, then python
	output, err := p.runPythonHelperCommand(ctx, "python3", args)
	if err != nil {
		var tooLarge *outputTooLargeError
		if errors.As(err, &tooLarge) {
			return nil, err
		}
		// Try with python if python3 failed
		output, err = p.runPythonHelperCommand(ctx, "python", args)
		if err != nil {
			if errors.As(err, &tooLarge) {
				return nil, err
			}
			return nil, fmt.Errorf("failed to run Python helper: %w", err)
		}
	}

	var helperOutput pyHelperOutput
	if err := json.Unmarshal(output, &helperOutput); err != nil {
		return nil, fmt.Errorf("failed to parse helper output: %w", err)
	}
	if helperOutput.Functions == nil {
		helperOutput.Functions = []pyHelperFunction{}
	}

	if helperOutput.Error != "" {
		return nil, fmt.Errorf("helper error: %s", helperOutput.Error)
	}

	return &helperOutput, nil
}

// findHelperScript locates the call_graph.py helper script.
func (p *PythonAnalyzer) findHelperScript() string {
	execPath, err := os.Executable()
	if err != nil {
		return ""
	}
	binDir := filepath.Dir(execPath)
	rootDir := filepath.Dir(binDir)
	searchPaths := []string{
		filepath.Join(rootDir, "py", "call_graph.py"),
		filepath.Join(rootDir, "scripts", "codereview", "py", "call_graph.py"),
	}

	for _, path := range searchPaths {
		cleaned := filepath.Clean(path)
		if !strings.HasPrefix(cleaned, rootDir+string(filepath.Separator)) && cleaned != rootDir {
			continue
		}
		if fileExists(cleaned) {
			return cleaned
		}
	}

	return ""
}

// processHelperResults converts Python helper output to CallGraphResult.
func (p *PythonAnalyzer) processHelperResults(helper *pyHelperOutput, modifiedFuncs []ModifiedFunction, result *CallGraphResult) (*CallGraphResult, error) {
	if helper == nil {
		return p.returnEmptyResults(modifiedFuncs, result), nil
	}

	// Build lookup maps
	funcLookup := make(map[string]*pyHelperFunction)
	for i := range helper.Functions {
		fn := &helper.Functions[i]
		key := fmt.Sprintf("%s:%s", fn.File, fn.Name)
		funcLookup[key] = fn
	}

	allDirectCallers := make(map[string]bool)
	allAffectedTests := make(map[string]bool)

	for _, modFunc := range modifiedFuncs {
		fcg := FunctionCallGraph{
			Function:     modFunc.Name,
			File:         modFunc.File,
			Callers:      make([]CallInfo, 0),
			Callees:      make([]CallInfo, 0),
			TestCoverage: make([]TestCoverage, 0),
		}

		// Find matching function in helper output
		key := fmt.Sprintf("%s:%s", modFunc.File, modFunc.Name)
		helperFunc := funcLookup[key]

		if helperFunc != nil {
			// Add callees from call sites
			for _, call := range helperFunc.CallSites {
				fcg.Callees = append(fcg.Callees, CallInfo{
					Function: call.Target,
					File:     modFunc.File,
					Line:     call.Line,
					CallSite: fmt.Sprintf("%s:%d", filepath.Base(modFunc.File), call.Line),
				})
			}

			// Add callers
			for _, caller := range helperFunc.CalledBy {
				callerKey := fmt.Sprintf("%s:%s", caller.File, caller.Function)
				allDirectCallers[callerKey] = true

				// Check if caller is a test
				if isPythonTestFile(caller.File) || isPythonTestFunction(caller.Function) {
					allAffectedTests[callerKey] = true
					fcg.TestCoverage = append(fcg.TestCoverage, TestCoverage{
						TestFunction: caller.Function,
						File:         caller.File,
						Line:         caller.Line,
					})
				}

				fcg.Callers = append(fcg.Callers, CallInfo{
					Function: caller.Function,
					File:     caller.File,
					Line:     caller.Line,
				})
			}
		}

		result.ModifiedFunctions = append(result.ModifiedFunctions, fcg)
	}

	result.ImpactAnalysis.DirectCallers = len(allDirectCallers)
	result.ImpactAnalysis.AffectedTests = len(allAffectedTests)

	return result, nil
}

// runPyan3 uses pyan3 as fallback for call graph analysis.
func (p *PythonAnalyzer) runPyan3(ctx context.Context, modifiedFuncs []ModifiedFunction, result *CallGraphResult) (*CallGraphResult, error) {
	// Collect files to analyze
	files := p.collectUniqueFiles(modifiedFuncs)
	if len(files) == 0 {
		return result, nil
	}

	// Sanitize file paths
	sanitizedFiles, err := p.sanitizeFilePaths(files)
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("file path validation failed: %v", err))
		return p.returnEmptyResults(modifiedFuncs, result), nil
	}

	// Try to run pyan3
	args := []string{"-e", "from pyan import main; main()", "--dot"}
	args = append(args, sanitizedFiles...)

	output, err := p.runPythonHelperCommand(ctx, "python3", args)
	if err != nil {
		var tooLarge *outputTooLargeError
		if errors.As(err, &tooLarge) {
			result.Warnings = append(result.Warnings, "pyan3 output exceeds size limit")
			return p.returnEmptyResults(modifiedFuncs, result), nil
		}

		// Try with pip-installed pyan3
		pyanArgs := append([]string{"--dot"}, sanitizedFiles...)
		output, err = p.runPythonHelperCommand(ctx, "pyan3", pyanArgs)
		if err != nil {
			if errors.As(err, &tooLarge) {
				result.Warnings = append(result.Warnings, "pyan3 output exceeds size limit")
				return p.returnEmptyResults(modifiedFuncs, result), nil
			}
			result.Warnings = append(result.Warnings, fmt.Sprintf("pyan3 not available: %v", err))
			return p.returnEmptyResults(modifiedFuncs, result), nil
		}
	}

	// Parse DOT output (basic parsing for caller/callee relationships)
	return p.parsePyanOutput(string(output), modifiedFuncs, result)
}

// parsePyanOutput parses pyan3 DOT format output.
func (p *PythonAnalyzer) parsePyanOutput(dotOutput string, modifiedFuncs []ModifiedFunction, result *CallGraphResult) (*CallGraphResult, error) {
	// Build a map of edges from DOT output
	// DOT format: "caller" -> "callee";
	edges := make(map[string][]string) // caller -> callees

	lines := strings.Split(dotOutput, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, "->") {
			continue
		}

		// Parse edge line
		parts := strings.Split(line, "->")
		if len(parts) != 2 {
			continue
		}

		rawCallee := strings.TrimSpace(strings.TrimSuffix(parts[1], ";"))
		if idx := strings.Index(rawCallee, "["); idx >= 0 {
			rawCallee = strings.TrimSpace(rawCallee[:idx])
		}

		caller := strings.Trim(strings.TrimSpace(parts[0]), "\"")
		callee := strings.Trim(strings.TrimSpace(rawCallee), "\"")

		if caller != "" && callee != "" {
			edges[caller] = append(edges[caller], callee)
		}
	}

	// Build reverse map for callers
	callerMap := make(map[string][]string) // callee -> callers
	for caller, callees := range edges {
		for _, callee := range callees {
			callerMap[callee] = append(callerMap[callee], caller)
		}
	}

	allDirectCallers := make(map[string]bool)
	allAffectedTests := make(map[string]bool)

	for _, modFunc := range modifiedFuncs {
		fcg := FunctionCallGraph{
			Function:     modFunc.Name,
			File:         modFunc.File,
			Callers:      make([]CallInfo, 0),
			Callees:      make([]CallInfo, 0),
			TestCoverage: make([]TestCoverage, 0),
		}

		// Find callees
		if callees, ok := edges[modFunc.Name]; ok {
			for _, callee := range callees {
				fcg.Callees = append(fcg.Callees, CallInfo{
					Function: callee,
				})
			}
		}

		// Find callers
		if callers, ok := callerMap[modFunc.Name]; ok {
			for _, caller := range callers {
				allDirectCallers[caller] = true

				// Check if caller is a test
				if isPythonTestFunction(caller) {
					allAffectedTests[caller] = true
					fcg.TestCoverage = append(fcg.TestCoverage, TestCoverage{
						TestFunction: caller,
					})
				}

				fcg.Callers = append(fcg.Callers, CallInfo{
					Function: caller,
				})
			}
		}

		result.ModifiedFunctions = append(result.ModifiedFunctions, fcg)
	}

	result.ImpactAnalysis.DirectCallers = len(allDirectCallers)
	result.ImpactAnalysis.AffectedTests = len(allAffectedTests)

	return result, nil
}

// returnEmptyResults returns partial results without call graph information.
func (p *PythonAnalyzer) returnEmptyResults(modifiedFuncs []ModifiedFunction, result *CallGraphResult) *CallGraphResult {
	for _, modFunc := range modifiedFuncs {
		result.ModifiedFunctions = append(result.ModifiedFunctions, FunctionCallGraph{
			Function:     modFunc.Name,
			File:         modFunc.File,
			Callers:      make([]CallInfo, 0),
			Callees:      make([]CallInfo, 0),
			TestCoverage: make([]TestCoverage, 0),
		})
	}
	return result
}

// isPythonTestFile checks if a file path indicates a test file.
func isPythonTestFile(filePath string) bool {
	base := filepath.Base(filePath)

	// Check for common test file patterns
	if strings.HasPrefix(base, "test_") {
		return true
	}
	if strings.HasSuffix(base, "_test.py") {
		return true
	}

	// Check if in tests directory
	normalizedPath := filepath.ToSlash(filePath)
	return strings.Contains(normalizedPath, "tests/") || strings.Contains(normalizedPath, "test/")
}

// isPythonTestFunction checks if a function name indicates a test function.
func isPythonTestFunction(funcName string) bool {
	// Remove class prefix if present
	parts := strings.Split(funcName, ".")
	baseName := parts[len(parts)-1]

	// Python unittest/pytest patterns
	return strings.HasPrefix(baseName, "test_") ||
		strings.HasPrefix(baseName, "Test") ||
		strings.HasSuffix(baseName, "_test")
}
