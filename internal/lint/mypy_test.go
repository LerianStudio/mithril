package lint

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapMypySeverity(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		expected Severity
	}{
		{"error returns high", "error", SeverityHigh},
		{"ERROR uppercase returns high", "ERROR", SeverityHigh},
		{"Error mixed case returns high", "Error", SeverityHigh},
		{"warning returns warning", "warning", SeverityWarning},
		{"WARNING uppercase returns warning", "WARNING", SeverityWarning},
		{"note returns info", "note", SeverityInfo},
		{"NOTE uppercase returns info", "NOTE", SeverityInfo},
		{"empty string returns warning", "", SeverityWarning},
		{"unknown severity returns warning", "unknown", SeverityWarning},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapMypySeverity(tt.severity)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMypy_Name(t *testing.T) {
	m := NewMypy()
	assert.Equal(t, "mypy", m.Name())
}

func TestMypy_Language(t *testing.T) {
	m := NewMypy()
	assert.Equal(t, LanguagePython, m.Language())
}

func TestMypyRun_ExecutionFailure(t *testing.T) {
	linter := NewMypy()
	executor := NewExecutor()
	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		if dir == "" {
			return &ExecResult{Stdout: []byte("mypy 1.8.0")}
		}
		return &ExecResult{Err: errors.New("boom"), Stdout: []byte{}}
	})
	linter.executor = executor

	result, err := linter.Run(context.Background(), "/tmp", []string{"main.py"})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Errors)
}

func TestMypyRun_ParseFailure(t *testing.T) {
	linter := NewMypy()
	executor := NewExecutor()
	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		if dir == "" {
			return &ExecResult{Stdout: []byte("mypy 1.8.0")}
		}
		return &ExecResult{Stdout: []byte("this is not json at all\nneither is this")}
	})
	linter.executor = executor

	result, err := linter.Run(context.Background(), "/tmp", []string{"main.py"})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Empty(t, result.Findings)
}

func TestMypyRun_Success(t *testing.T) {
	linter := NewMypy()
	executor := NewExecutor()
	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		if dir == "" {
			return &ExecResult{Stdout: []byte("mypy 1.8.0")}
		}
		return &ExecResult{Stdout: []byte(`{"file":"main.py","line":10,"column":5,"severity":"error","code":"assignment","message":"Incompatible types in assignment"}` + "\n")}
	})
	linter.executor = executor

	result, err := linter.Run(context.Background(), "/project", []string{"main.py"})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, SeverityHigh, result.Findings[0].Severity)
	assert.Equal(t, CategoryType, result.Findings[0].Category)
	assert.Equal(t, "assignment", result.Findings[0].Rule)
}
