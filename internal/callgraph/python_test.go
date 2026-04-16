package callgraph

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPythonAnalyzerAnalyze_EmptyInput(t *testing.T) {
	analyzer := NewPythonAnalyzer(t.TempDir())
	result, err := analyzer.Analyze([]ModifiedFunction{}, 30)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if len(result.ModifiedFunctions) != 0 {
		t.Fatalf("expected no modified functions, got %d", len(result.ModifiedFunctions))
	}
}

func TestPythonAnalyzerAnalyze_TruncationAndDefaultBudget(t *testing.T) {
	analyzer := NewPythonAnalyzer(t.TempDir())
	seen := 0
	hadDeadline := false
	analyzer.runHelperFn = func(ctx context.Context, files []string, modifiedFuncs []ModifiedFunction) (*pyHelperOutput, error) {
		seen = len(modifiedFuncs)
		_, hadDeadline = ctx.Deadline()
		return &pyHelperOutput{}, nil
	}
	analyzer.processHelperFn = func(helper *pyHelperOutput, modifiedFuncs []ModifiedFunction, result *CallGraphResult) (*CallGraphResult, error) {
		return analyzer.returnEmptyResults(modifiedFuncs, result), nil
	}

	modified := make([]ModifiedFunction, pyMaxModifiedFunctions+50)
	for i := range modified {
		modified[i] = ModifiedFunction{Name: fmt.Sprintf("fn_%d", i), File: fmt.Sprintf("file_%d.py", i)}
	}

	result, err := analyzer.Analyze(modified, 0)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if !result.PartialResults {
		t.Fatal("expected partial results when input is truncated")
	}
	if seen != pyMaxModifiedFunctions {
		t.Fatalf("expected helper to receive %d functions, got %d", pyMaxModifiedFunctions, seen)
	}
	if !hadDeadline {
		t.Fatal("expected default time budget to set a context deadline")
	}
	if len(result.ModifiedFunctions) != pyMaxModifiedFunctions {
		t.Fatalf("expected %d modified function entries, got %d", pyMaxModifiedFunctions, len(result.ModifiedFunctions))
	}
}

func TestPythonAnalyzerAnalyze_FallbackOnHelperError(t *testing.T) {
	analyzer := NewPythonAnalyzer(t.TempDir())
	fallbackCalled := false
	analyzer.runHelperFn = func(ctx context.Context, files []string, modifiedFuncs []ModifiedFunction) (*pyHelperOutput, error) {
		return nil, errors.New("helper unavailable")
	}
	analyzer.runFallbackFn = func(ctx context.Context, modifiedFuncs []ModifiedFunction, result *CallGraphResult) (*CallGraphResult, error) {
		fallbackCalled = true
		return analyzer.returnEmptyResults(modifiedFuncs, result), nil
	}

	result, err := analyzer.Analyze([]ModifiedFunction{{Name: "CreateUser", File: "service.py"}}, 5)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if !fallbackCalled {
		t.Fatal("expected fallback analyzer to be invoked")
	}
	if len(result.Warnings) == 0 || !strings.Contains(result.Warnings[0], "Python helper unavailable") {
		t.Fatalf("expected helper warning, got %v", result.Warnings)
	}
}

func TestPythonAnalyzerSanitizeFilePaths(t *testing.T) {
	workDir := t.TempDir()
	analyzer := NewPythonAnalyzer(workDir)

	validFile := filepath.Join(workDir, "service.py")
	if err := os.WriteFile(validFile, []byte("def run():\n    pass\n"), 0o644); err != nil {
		t.Fatalf("failed to write valid file: %v", err)
	}

	if _, err := analyzer.sanitizeFilePaths([]string{validFile}); err != nil {
		t.Fatalf("expected valid file path to pass, got: %v", err)
	}

	if _, err := analyzer.sanitizeFilePaths([]string{"-exec"}); err == nil {
		t.Fatal("expected dash-prefixed path to fail")
	}
	if _, err := analyzer.sanitizeFilePaths([]string{"file\x00.py"}); err == nil {
		t.Fatal("expected null-byte path to fail")
	}
	if _, err := analyzer.sanitizeFilePaths([]string{"../../etc/passwd"}); err == nil {
		t.Fatal("expected traversal path to fail")
	}

	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "secret.py")
	if err := os.WriteFile(outsideFile, []byte("print('secret')\n"), 0o644); err != nil {
		t.Fatalf("failed to write outside file: %v", err)
	}
	symlinkPath := filepath.Join(workDir, "escape.py")
	if err := os.Symlink(outsideFile, symlinkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}
	if _, err := analyzer.sanitizeFilePaths([]string{symlinkPath}); err == nil {
		t.Fatal("expected symlink escape to fail")
	}

	danglingTarget := filepath.Join(outsideDir, "missing.py")
	danglingLink := filepath.Join(workDir, "dangling.py")
	if err := os.Symlink(danglingTarget, danglingLink); err != nil {
		t.Fatalf("failed to create dangling symlink: %v", err)
	}
	if _, err := analyzer.sanitizeFilePaths([]string{danglingLink}); err == nil {
		t.Fatal("expected dangling symlink to fail")
	}
}

func TestPythonAnalyzerSanitizeFunctionNames(t *testing.T) {
	analyzer := NewPythonAnalyzer(t.TempDir())

	valid, err := analyzer.sanitizeFunctionNames([]string{"create_user", "repo.save", "UserService.create"})
	if err != nil {
		t.Fatalf("expected valid function names to pass: %v", err)
	}
	if len(valid) != 3 {
		t.Fatalf("expected 3 valid function names, got %d", len(valid))
	}

	if _, err := analyzer.sanitizeFunctionNames([]string{"-danger"}); err == nil {
		t.Fatal("expected dash-prefixed function name to fail")
	}

	if _, err := analyzer.sanitizeFunctionNames([]string{"bad name"}); err == nil {
		t.Fatal("expected invalid identifier to fail")
	}
}

func TestPythonAnalyzerProcessHelperResults(t *testing.T) {
	analyzer := NewPythonAnalyzer(t.TempDir())
	helper := &pyHelperOutput{
		Functions: []pyHelperFunction{
			{
				Name: "create_user",
				File: "service.py",
				CallSites: []pyHelperCall{
					{Target: "repo.insert", Line: 15},
				},
				CalledBy: []pyHelperCaller{
					{Function: "test_create_user", File: "tests/test_service.py", Line: 8},
				},
			},
		},
	}

	result := &CallGraphResult{ModifiedFunctions: []FunctionCallGraph{}, Warnings: []string{}, ImpactAnalysis: ImpactAnalysis{}}
	modified := []ModifiedFunction{{Name: "create_user", File: "service.py"}}

	out, err := analyzer.processHelperResults(helper, modified, result)
	if err != nil {
		t.Fatalf("processHelperResults returned error: %v", err)
	}
	if len(out.ModifiedFunctions) != 1 {
		t.Fatalf("expected 1 modified function graph, got %d", len(out.ModifiedFunctions))
	}
	if len(out.ModifiedFunctions[0].Callees) != 1 {
		t.Fatalf("expected 1 callee, got %d", len(out.ModifiedFunctions[0].Callees))
	}
	if len(out.ModifiedFunctions[0].TestCoverage) != 1 {
		t.Fatalf("expected 1 test coverage entry, got %d", len(out.ModifiedFunctions[0].TestCoverage))
	}
	if out.ImpactAnalysis.DirectCallers != 1 {
		t.Fatalf("expected 1 direct caller, got %d", out.ImpactAnalysis.DirectCallers)
	}
	if out.ImpactAnalysis.AffectedTests != 1 {
		t.Fatalf("expected 1 affected test, got %d", out.ImpactAnalysis.AffectedTests)
	}
}

func TestPythonAnalyzerProcessHelperResults_NilHelper(t *testing.T) {
	analyzer := NewPythonAnalyzer(t.TempDir())
	result := &CallGraphResult{ModifiedFunctions: []FunctionCallGraph{}, Warnings: []string{}, ImpactAnalysis: ImpactAnalysis{}}
	modified := []ModifiedFunction{{Name: "create_user", File: "service.py"}}

	out, err := analyzer.processHelperResults(nil, modified, result)
	if err != nil {
		t.Fatalf("processHelperResults returned error: %v", err)
	}
	if len(out.ModifiedFunctions) != 1 {
		t.Fatalf("expected 1 modified function graph for nil helper, got %d", len(out.ModifiedFunctions))
	}
	if len(out.ModifiedFunctions[0].Callers) != 0 || len(out.ModifiedFunctions[0].Callees) != 0 {
		t.Fatalf("expected empty callgraph for nil helper, got %+v", out.ModifiedFunctions[0])
	}
}

func TestIsPythonTestFile(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		expected bool
	}{
		// Test file patterns
		{name: "test_ prefix", filePath: "test_utils.py", expected: true},
		{name: "_test.py suffix", filePath: "utils_test.py", expected: true},
		{name: "in tests/ directory", filePath: "tests/test_handler.py", expected: true},
		{name: "in test/ directory", filePath: "test/helper.py", expected: true},
		{name: "nested tests/ directory", filePath: "src/tests/integration.py", expected: true},

		// Non-test files
		{name: "regular python file", filePath: "utils.py", expected: false},
		{name: "conftest is not matched by prefix/suffix", filePath: "conftest.py", expected: false},
		{name: "file with test in name but not pattern", filePath: "testing_helpers.py", expected: false},
		{name: "file with test in middle", filePath: "my_testing.py", expected: false},
		{name: "directory-only match", filePath: "src/main.py", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPythonTestFile(tt.filePath)
			if result != tt.expected {
				t.Errorf("isPythonTestFile(%q) = %v, want %v", tt.filePath, result, tt.expected)
			}
		})
	}
}

func TestIsPythonTestFunction(t *testing.T) {
	tests := []struct {
		name     string
		funcName string
		expected bool
	}{
		// Test function patterns
		{name: "test_ prefix", funcName: "test_something", expected: true},
		{name: "Test class prefix", funcName: "TestSomething", expected: true},
		{name: "_test suffix", funcName: "something_test", expected: true},
		{name: "class.test_ method", funcName: "TestClass.test_method", expected: true},

		// Non-test functions
		{name: "regular function", funcName: "process_data", expected: false},
		{name: "setup function", funcName: "setup", expected: false},
		{name: "helper function", funcName: "create_test_data", expected: false},
		{name: "contains test but no pattern", funcName: "testing", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPythonTestFunction(tt.funcName)
			if result != tt.expected {
				t.Errorf("isPythonTestFunction(%q) = %v, want %v", tt.funcName, result, tt.expected)
			}
		})
	}
}

func TestPythonAnalyzerParsePyanOutput(t *testing.T) {
	analyzer := NewPythonAnalyzer(t.TempDir())
	result := &CallGraphResult{ModifiedFunctions: []FunctionCallGraph{}, Warnings: []string{}, ImpactAnalysis: ImpactAnalysis{}}

	dot := strings.Join([]string{
		"digraph G {",
		"  // comment line",
		"  \"test_create_user\" -> \"create_user\";",
		"  \"create_user\" -> \"repo.insert\" [style=dashed];",
		"}",
	}, "\n")

	modified := []ModifiedFunction{{Name: "create_user", File: "service.py"}}
	out, err := analyzer.parsePyanOutput(dot, modified, result)
	if err != nil {
		t.Fatalf("parsePyanOutput returned error: %v", err)
	}
	if len(out.ModifiedFunctions) != 1 {
		t.Fatalf("expected 1 modified function, got %d", len(out.ModifiedFunctions))
	}
	fcg := out.ModifiedFunctions[0]
	if len(fcg.Callers) != 1 || fcg.Callers[0].Function != "test_create_user" {
		t.Fatalf("unexpected callers: %+v", fcg.Callers)
	}
	if len(fcg.Callees) != 1 || fcg.Callees[0].Function != "repo.insert" {
		t.Fatalf("unexpected callees: %+v", fcg.Callees)
	}
	if len(fcg.TestCoverage) != 1 || fcg.TestCoverage[0].TestFunction != "test_create_user" {
		t.Fatalf("unexpected test coverage: %+v", fcg.TestCoverage)
	}
	if out.ImpactAnalysis.DirectCallers != 1 {
		t.Fatalf("expected 1 direct caller, got %d", out.ImpactAnalysis.DirectCallers)
	}
	if out.ImpactAnalysis.AffectedTests != 1 {
		t.Fatalf("expected 1 affected test, got %d", out.ImpactAnalysis.AffectedTests)
	}
}

func TestPythonAnalyzerRunPythonHelperCommand_TooLarge(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell command differs on windows")
	}

	analyzer := NewPythonAnalyzer(t.TempDir())
	cmd := fmt.Sprintf("head -c %d /dev/zero", maxHelperOutputSize+1)

	_, err := analyzer.runPythonHelperCommand(context.Background(), "sh", []string{"-c", cmd})
	if err == nil {
		t.Fatal("expected oversized output to fail")
	}
	if !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("expected size limit error, got: %v", err)
	}
}
