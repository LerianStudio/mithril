package lint

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapTSCSeverity(t *testing.T) {
	tests := []struct {
		name     string
		level    string
		expected Severity
	}{
		{"error returns high", "error", SeverityHigh},
		{"ERROR uppercase returns high", "ERROR", SeverityHigh},
		{"Error mixed case returns high", "Error", SeverityHigh},
		{"warning returns warning", "warning", SeverityWarning},
		{"WARNING uppercase returns warning", "WARNING", SeverityWarning},
		{"Warning mixed case returns warning", "Warning", SeverityWarning},
		{"info returns info", "info", SeverityInfo},
		{"empty string returns info", "", SeverityInfo},
		{"unknown level returns info", "unknown", SeverityInfo},
		{"note returns info", "note", SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapTSCSeverity(tt.level)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTSC_Name(t *testing.T) {
	tsc := NewTSC()
	assert.Equal(t, "tsc", tsc.Name())
}

func TestTSC_Language(t *testing.T) {
	tsc := NewTSC()
	assert.Equal(t, LanguageTypeScript, tsc.Language())
}

func TestTSCRun_ExecutionFailure(t *testing.T) {
	linter := NewTSC()
	executor := NewExecutor()
	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		if dir == "" {
			return &ExecResult{Stdout: []byte("Version 5.3.3")}
		}
		return &ExecResult{Err: errors.New("boom")}
	})
	linter.executor = executor

	result, err := linter.Run(context.Background(), "/tmp", []string{})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Errors)
}

func TestTSCRun_ParseFailure(t *testing.T) {
	linter := NewTSC()
	executor := NewExecutor()
	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		if dir == "" {
			return &ExecResult{Stdout: []byte("Version 5.3.3")}
		}
		return &ExecResult{Stdout: []byte("this is not a valid tsc diagnostic line")}
	})
	linter.executor = executor

	result, err := linter.Run(context.Background(), "/tmp", []string{})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Empty(t, result.Findings)
}

func TestTSCRun_Success(t *testing.T) {
	linter := NewTSC()
	executor := NewExecutor()
	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		if dir == "" {
			return &ExecResult{Stdout: []byte("Version 5.3.3")}
		}
		return &ExecResult{Stdout: []byte("src/index.ts(10,5): error TS2322: Type 'string' is not assignable to type 'number'.\n")}
	})
	linter.executor = executor

	result, err := linter.Run(context.Background(), "/project", []string{})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, SeverityHigh, result.Findings[0].Severity)
	assert.Equal(t, CategoryType, result.Findings[0].Category)
	assert.Equal(t, "TS2322", result.Findings[0].Rule)
	assert.Equal(t, 10, result.Findings[0].Line)
	assert.Equal(t, 5, result.Findings[0].Column)
}

func TestTSCRun_UsesNoInstallInNPXInvocation(t *testing.T) {
	linter := NewTSC()
	executor := NewExecutor()
	type invocation struct {
		dir  string
		name string
		args []string
	}
	var calls []invocation

	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		calls = append(calls, invocation{dir: dir, name: name, args: append([]string{}, args...)})
		if dir == "" {
			return &ExecResult{Stdout: []byte("Version 5.3.3")}
		}
		return &ExecResult{Stdout: []byte(""), ExitCode: 0}
	})
	linter.executor = executor

	result, err := linter.Run(context.Background(), "/project", []string{"src/index.ts"})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.GreaterOrEqual(t, len(calls), 2)

	last := calls[len(calls)-1]
	assert.Equal(t, "npx", last.name)
	require.GreaterOrEqual(t, len(last.args), 4)
	assert.Equal(t, "--no-install", last.args[0])
	assert.Equal(t, "tsc", last.args[1])
	assert.Equal(t, "--noEmit", last.args[2])
}

func TestTSCRun_InvalidTargetRejected(t *testing.T) {
	linter := NewTSC()
	executor := NewExecutor()
	runCalls := 0

	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		if dir == "" {
			return &ExecResult{Stdout: []byte("Version 5.3.3")}
		}
		runCalls++
		return &ExecResult{Stdout: []byte(""), ExitCode: 0}
	})
	linter.executor = executor

	result, err := linter.Run(context.Background(), "/project", []string{"--fix"})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotEmpty(t, result.Errors)
	assert.Contains(t, result.Errors[0], "target validation failed")
	assert.Equal(t, 0, runCalls)
}
