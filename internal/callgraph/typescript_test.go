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

func TestTypeScriptAnalyzerAnalyze_EmptyInput(t *testing.T) {
	analyzer := NewTypeScriptAnalyzer(t.TempDir())
	result, err := analyzer.Analyze([]ModifiedFunction{}, 30)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if len(result.ModifiedFunctions) != 0 {
		t.Fatalf("expected no modified functions, got %d", len(result.ModifiedFunctions))
	}
}

func TestTypeScriptAnalyzerAnalyze_Truncation(t *testing.T) {
	analyzer := NewTypeScriptAnalyzer(t.TempDir())
	seen := 0
	analyzer.runHelperFn = func(ctx context.Context, files []string, modifiedFuncs []ModifiedFunction) (*tsHelperOutput, error) {
		seen = len(modifiedFuncs)
		return &tsHelperOutput{}, nil
	}
	analyzer.processHelperFn = func(helper *tsHelperOutput, modifiedFuncs []ModifiedFunction, result *CallGraphResult) (*CallGraphResult, error) {
		for _, fn := range modifiedFuncs {
			result.ModifiedFunctions = append(result.ModifiedFunctions, FunctionCallGraph{
				Function:     fn.Name,
				File:         fn.File,
				Callers:      []CallInfo{},
				Callees:      []CallInfo{},
				TestCoverage: []TestCoverage{},
			})
		}
		return result, nil
	}

	modified := make([]ModifiedFunction, tsMaxModifiedFunctions+25)
	for i := range modified {
		modified[i] = ModifiedFunction{Name: fmt.Sprintf("fn_%d", i), File: fmt.Sprintf("file_%d.ts", i)}
	}

	result, err := analyzer.Analyze(modified, 1)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if !result.PartialResults {
		t.Fatal("expected partial results when input is truncated")
	}
	if seen != tsMaxModifiedFunctions {
		t.Fatalf("expected helper to receive %d functions, got %d", tsMaxModifiedFunctions, seen)
	}
}

func TestTypeScriptAnalyzerAnalyze_FallbackOnHelperError(t *testing.T) {
	analyzer := NewTypeScriptAnalyzer(t.TempDir())
	fallbackCalled := false
	analyzer.runHelperFn = func(ctx context.Context, files []string, modifiedFuncs []ModifiedFunction) (*tsHelperOutput, error) {
		return nil, errors.New("helper failed")
	}
	analyzer.runFallbackFn = func(ctx context.Context, modifiedFuncs []ModifiedFunction, result *CallGraphResult) (*CallGraphResult, error) {
		fallbackCalled = true
		for _, fn := range modifiedFuncs {
			result.ModifiedFunctions = append(result.ModifiedFunctions, FunctionCallGraph{
				Function:     fn.Name,
				File:         fn.File,
				Callers:      []CallInfo{},
				Callees:      []CallInfo{},
				TestCoverage: []TestCoverage{},
			})
		}
		return result, nil
	}

	result, err := analyzer.Analyze([]ModifiedFunction{{Name: "createUser", File: "service.ts"}}, 5)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if !fallbackCalled {
		t.Fatal("expected dep-cruiser fallback to be invoked")
	}
	if len(result.Warnings) == 0 || !strings.Contains(result.Warnings[0], "TypeScript helper unavailable") {
		t.Fatalf("expected helper warning, got %v", result.Warnings)
	}
}

func TestTypeScriptAnalyzerAnalyze_TypeCheckerUnavailableFallback(t *testing.T) {
	analyzer := NewTypeScriptAnalyzer(t.TempDir())
	fallbackCalled := false
	analyzer.runHelperFn = func(ctx context.Context, files []string, modifiedFuncs []ModifiedFunction) (*tsHelperOutput, error) {
		return &tsHelperOutput{Error: "Type checker unavailable"}, nil
	}
	analyzer.runFallbackFn = func(ctx context.Context, modifiedFuncs []ModifiedFunction, result *CallGraphResult) (*CallGraphResult, error) {
		fallbackCalled = true
		return result, nil
	}

	result, err := analyzer.Analyze([]ModifiedFunction{{Name: "createUser", File: "service.ts"}}, 5)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if !fallbackCalled {
		t.Fatal("expected fallback for type checker unavailable")
	}
	if len(result.Warnings) == 0 || !strings.Contains(result.Warnings[len(result.Warnings)-1], "type checker") {
		t.Fatalf("expected type checker warning, got %v", result.Warnings)
	}
}

func TestTypeScriptAnalyzerSanitizeFilePaths(t *testing.T) {
	workDir := t.TempDir()
	analyzer := NewTypeScriptAnalyzer(workDir)

	validFile := filepath.Join(workDir, "service.ts")
	if err := os.WriteFile(validFile, []byte("export const x = 1\n"), 0o644); err != nil {
		t.Fatalf("failed to write valid file: %v", err)
	}

	if _, err := analyzer.sanitizeFilePaths([]string{validFile}); err != nil {
		t.Fatalf("expected valid file path to pass, got: %v", err)
	}

	if _, err := analyzer.sanitizeFilePaths([]string{"-exec"}); err == nil {
		t.Fatal("expected dash-prefixed path to fail")
	}
	if _, err := analyzer.sanitizeFilePaths([]string{"file\x00.ts"}); err == nil {
		t.Fatal("expected null-byte path to fail")
	}
	if _, err := analyzer.sanitizeFilePaths([]string{"../../etc/passwd"}); err == nil {
		t.Fatal("expected traversal path to fail")
	}

	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "secret.ts")
	if err := os.WriteFile(outsideFile, []byte("export const secret = true\n"), 0o644); err != nil {
		t.Fatalf("failed to write outside file: %v", err)
	}
	symlinkPath := filepath.Join(workDir, "escape.ts")
	if err := os.Symlink(outsideFile, symlinkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}
	if _, err := analyzer.sanitizeFilePaths([]string{symlinkPath}); err == nil {
		t.Fatal("expected symlink escape to fail")
	}

	danglingTarget := filepath.Join(outsideDir, "missing.ts")
	danglingLink := filepath.Join(workDir, "dangling.ts")
	if err := os.Symlink(danglingTarget, danglingLink); err != nil {
		t.Fatalf("failed to create dangling symlink: %v", err)
	}
	if _, err := analyzer.sanitizeFilePaths([]string{danglingLink}); err == nil {
		t.Fatal("expected dangling symlink to fail")
	}
}

func TestTypeScriptAnalyzerSanitizeFunctionNames(t *testing.T) {
	analyzer := NewTypeScriptAnalyzer(t.TempDir())

	if _, err := analyzer.sanitizeFunctionNames([]string{"handler", "Service.process", "$internal"}); err != nil {
		t.Fatalf("expected valid function names to pass, got: %v", err)
	}

	if _, err := analyzer.sanitizeFunctionNames([]string{"-malicious"}); err == nil {
		t.Fatal("expected dash-prefixed function name to fail")
	}

	if _, err := analyzer.sanitizeFunctionNames([]string{"invalid name"}); err == nil {
		t.Fatal("expected invalid identifier to fail")
	}
}

func TestTypeScriptAnalyzerRunHelperCommandWithLimit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell command differs on windows")
	}

	analyzer := NewTypeScriptAnalyzer(t.TempDir())

	output, err := analyzer.runHelperCommandWithLimit(context.Background(), "sh", []string{"-c", "printf 'ok'"})
	if err != nil {
		t.Fatalf("expected small output to succeed, got: %v", err)
	}
	if string(output) != "ok" {
		t.Fatalf("unexpected output: %q", string(output))
	}
}

func TestTypeScriptAnalyzerRunHelperCommandWithLimit_TooLarge(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell command differs on windows")
	}

	analyzer := NewTypeScriptAnalyzer(t.TempDir())
	cmd := fmt.Sprintf("head -c %d /dev/zero", maxHelperOutputSize+1)

	_, err := analyzer.runHelperCommandWithLimit(context.Background(), "sh", []string{"-c", cmd})
	if err == nil {
		t.Fatal("expected oversized output to fail")
	}
	if !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("expected size limit error, got: %v", err)
	}
}

func TestTypeScriptAnalyzerProcessHelperResults(t *testing.T) {
	analyzer := NewTypeScriptAnalyzer(t.TempDir())
	helper := &tsHelperOutput{
		Functions: []tsHelperFunction{
			{
				Name: "createUser",
				File: "service.ts",
				CallSites: []tsHelperCall{
					{Target: "repo.insert", Line: 15},
				},
				CalledBy: []tsHelperCaller{
					{Function: "test_createUser", File: "tests/service.test.ts", Line: 8},
				},
			},
		},
	}

	result := &CallGraphResult{ModifiedFunctions: []FunctionCallGraph{}, Warnings: []string{}, ImpactAnalysis: ImpactAnalysis{}}
	modified := []ModifiedFunction{{Name: "createUser", File: "service.ts"}}

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

func TestTypeScriptAnalyzerProcessHelperResults_NilHelper(t *testing.T) {
	analyzer := NewTypeScriptAnalyzer(t.TempDir())
	result := &CallGraphResult{ModifiedFunctions: []FunctionCallGraph{}, Warnings: []string{}, ImpactAnalysis: ImpactAnalysis{}}
	modified := []ModifiedFunction{{Name: "createUser", File: "service.ts"}}

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

func TestIsTypeScriptTestFile(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		expected bool
	}{
		// Test file patterns
		{name: ".test.ts file", filePath: "utils.test.ts", expected: true},
		{name: ".spec.ts file", filePath: "utils.spec.ts", expected: true},
		{name: ".test.tsx file", filePath: "Component.test.tsx", expected: true},
		{name: ".spec.tsx file", filePath: "Component.spec.tsx", expected: true},
		{name: "_test.ts file", filePath: "utils_test.ts", expected: true},
		{name: "_spec.ts file", filePath: "utils_spec.ts", expected: true},
		{name: "in __tests__ directory", filePath: "src/__tests__/utils.ts", expected: true},
		{name: "in /test/ directory", filePath: "src/test/helpers.ts", expected: true},
		{name: "in /tests/ directory", filePath: "src/tests/integration.ts", expected: true},
		{name: "top-level test/ not matched without leading slash", filePath: "test/helpers.ts", expected: false},
		{name: "top-level tests/ not matched without leading slash", filePath: "tests/integration.ts", expected: false},

		// Non-test files
		{name: "regular ts file", filePath: "utils.ts", expected: false},
		{name: "regular tsx file", filePath: "Component.tsx", expected: false},
		{name: "file with test in name", filePath: "testUtils.ts", expected: false},
		{name: "source file in src/", filePath: "src/handler.ts", expected: false},
		{name: "declaration file", filePath: "types.d.ts", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isTypeScriptTestFile(tt.filePath)
			if result != tt.expected {
				t.Errorf("isTypeScriptTestFile(%q) = %v, want %v", tt.filePath, result, tt.expected)
			}
		})
	}
}

func TestIsTypeScriptTestFunction(t *testing.T) {
	tests := []struct {
		name     string
		funcName string
		expected bool
	}{
		// Test framework functions (exact matches)
		{name: "it function", funcName: "it", expected: true},
		{name: "test function", funcName: "test", expected: true},
		{name: "describe function", funcName: "describe", expected: true},
		{name: "beforeEach", funcName: "beforeEach", expected: true},
		{name: "afterEach", funcName: "afterEach", expected: true},
		{name: "beforeAll", funcName: "beforeAll", expected: true},
		{name: "afterAll", funcName: "afterAll", expected: true},

		// Prefix matches
		{name: "test_ prefix", funcName: "test_something", expected: true},
		{name: "spec_ prefix", funcName: "spec_something", expected: true},
		{name: "TEST_ uppercase prefix", funcName: "TEST_something", expected: true},

		// Non-test functions
		{name: "regular function", funcName: "processData", expected: false},
		{name: "helper function", funcName: "createMock", expected: false},
		{name: "contains test but not prefix", funcName: "getTestData", expected: false},
		{name: "iterator", funcName: "iterate", expected: false},
		{name: "empty string", funcName: "", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isTypeScriptTestFunction(tt.funcName)
			if result != tt.expected {
				t.Errorf("isTypeScriptTestFunction(%q) = %v, want %v", tt.funcName, result, tt.expected)
			}
		})
	}
}
