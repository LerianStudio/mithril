package lint

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapPylintSeverity(t *testing.T) {
	tests := []struct {
		name     string
		msgType  string
		expected Severity
	}{
		{"fatal returns high", "fatal", SeverityHigh},
		{"FATAL uppercase returns high", "FATAL", SeverityHigh},
		{"error returns high", "error", SeverityHigh},
		{"ERROR uppercase returns high", "ERROR", SeverityHigh},
		{"warning returns warning", "warning", SeverityWarning},
		{"WARNING uppercase returns warning", "WARNING", SeverityWarning},
		{"refactor returns info", "refactor", SeverityInfo},
		{"REFACTOR uppercase returns info", "REFACTOR", SeverityInfo},
		{"convention returns info", "convention", SeverityInfo},
		{"CONVENTION uppercase returns info", "CONVENTION", SeverityInfo},
		{"empty string returns info", "", SeverityInfo},
		{"unknown type returns info", "unknown", SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapPylintSeverity(tt.msgType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMapPylintCategory(t *testing.T) {
	tests := []struct {
		name     string
		msgType  string
		msgID    string
		expected Category
	}{
		{"fatal returns bug", "fatal", "F0001", CategoryBug},
		{"error returns bug", "error", "E0001", CategoryBug},
		{"warning W0611 returns unused", "warning", "W0611", CategoryUnused},
		{"warning W0612 returns unused", "warning", "W0612", CategoryUnused},
		{"warning W0613 returns bug", "warning", "W0613", CategoryBug},
		{"warning other returns bug", "warning", "W0001", CategoryBug},
		{"refactor returns complexity", "refactor", "R0001", CategoryComplexity},
		{"convention returns style", "convention", "C0001", CategoryStyle},
		{"unknown type returns other", "unknown", "X0001", CategoryOther},
		{"empty type returns other", "", "X0001", CategoryOther},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapPylintCategory(tt.msgType, tt.msgID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPylint_Name(t *testing.T) {
	p := NewPylint()
	assert.Equal(t, "pylint", p.Name())
}

func TestPylint_Language(t *testing.T) {
	p := NewPylint()
	assert.Equal(t, LanguagePython, p.Language())
}

func TestPylintRun_ExecutionFailure(t *testing.T) {
	linter := NewPylint()
	executor := NewExecutor()
	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		if dir == "" {
			return &ExecResult{Stdout: []byte("pylint 3.0.3")}
		}
		return &ExecResult{Err: errors.New("boom")}
	})
	linter.executor = executor

	result, err := linter.Run(context.Background(), "/tmp", []string{"main.py"})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Errors)
}

func TestPylintRun_ParseFailure(t *testing.T) {
	linter := NewPylint()
	executor := NewExecutor()
	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		if dir == "" {
			return &ExecResult{Stdout: []byte("pylint 3.0.3")}
		}
		return &ExecResult{Stdout: []byte("{broken")}
	})
	linter.executor = executor

	result, err := linter.Run(context.Background(), "/tmp", []string{"main.py"})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Errors)
	assert.Empty(t, result.Findings)
}

func TestPylintRun_Success(t *testing.T) {
	linter := NewPylint()
	executor := NewExecutor()
	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		if dir == "" {
			return &ExecResult{Stdout: []byte("pylint 3.0.3")}
		}
		return &ExecResult{Stdout: []byte(`[{"type":"convention","module":"main","obj":"","line":1,"column":0,"path":"main.py","symbol":"missing-module-docstring","message":"Missing module docstring","message-id":"C0114"}]`)}
	})
	linter.executor = executor

	result, err := linter.Run(context.Background(), "/project", []string{"main.py"})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, SeverityInfo, result.Findings[0].Severity)
	assert.Equal(t, CategoryStyle, result.Findings[0].Category)
	assert.Equal(t, "C0114", result.Findings[0].Rule)
}
