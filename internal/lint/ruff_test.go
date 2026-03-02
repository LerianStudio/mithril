package lint

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapRuffSeverity(t *testing.T) {
	tests := []struct {
		code     string
		expected Severity
	}{
		{"S101", SeverityHigh},    // Security
		{"S501", SeverityHigh},    // Security
		{"E501", SeverityWarning}, // Errors
		{"F401", SeverityWarning}, // Pyflakes
		{"W503", SeverityWarning}, // Warnings
		{"B001", SeverityWarning}, // Bugbear
		{"I001", SeverityInfo},    // Import sorting
		{"D100", SeverityInfo},    // Docstring
		{"N801", SeverityInfo},    // Naming
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			result := mapRuffSeverity(tt.code)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMapRuffCategory(t *testing.T) {
	tests := []struct {
		code     string
		expected Category
	}{
		{"S101", CategorySecurity},
		{"S501", CategorySecurity},
		{"F401", CategoryBug},
		{"F841", CategoryBug},
		{"E501", CategoryStyle},
		{"E302", CategoryStyle},
		{"W503", CategoryStyle},
		{"W291", CategoryStyle},
		{"B001", CategoryBug},
		{"B007", CategoryBug},
		{"I001", CategoryStyle},
		{"UP001", CategoryDeprecation},
		{"UP035", CategoryDeprecation},
		{"C901", CategoryComplexity},
		{"D100", CategoryOther},
		{"Z999", CategoryOther},
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			result := mapRuffCategory(tt.code)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRuff_Name(t *testing.T) {
	r := NewRuff()
	assert.Equal(t, "ruff", r.Name())
}

func TestRuff_Language(t *testing.T) {
	r := NewRuff()
	assert.Equal(t, LanguagePython, r.Language())
}

func TestRuffRun_ExecutionFailure(t *testing.T) {
	linter := NewRuff()
	executor := NewExecutor()
	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		if dir == "" {
			return &ExecResult{Stdout: []byte("ruff 0.1.9")}
		}
		return &ExecResult{Err: errors.New("boom")}
	})
	linter.executor = executor

	result, err := linter.Run(context.Background(), "/tmp", []string{"main.py"})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Errors)
}

func TestRuffRun_ParseFailure(t *testing.T) {
	linter := NewRuff()
	executor := NewExecutor()
	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		if dir == "" {
			return &ExecResult{Stdout: []byte("ruff 0.1.9")}
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

func TestRuffRun_Success(t *testing.T) {
	linter := NewRuff()
	executor := NewExecutor()
	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		if dir == "" {
			return &ExecResult{Stdout: []byte("ruff 0.1.9")}
		}
		return &ExecResult{Stdout: []byte(`[{"code":"F401","message":"os imported but unused","location":{"row":1,"column":8},"fix":{"message":"Remove unused import: os"},"filename":"/project/main.py"}]`)}
	})
	linter.executor = executor

	result, err := linter.Run(context.Background(), "/project", []string{"main.py"})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, SeverityWarning, result.Findings[0].Severity)
	assert.Equal(t, CategoryBug, result.Findings[0].Category)
	assert.Equal(t, "F401", result.Findings[0].Rule)
	assert.Equal(t, "Remove unused import: os", result.Findings[0].Suggestion)
}

func TestRuffRun_SuccessWithoutFix(t *testing.T) {
	linter := NewRuff()
	executor := NewExecutor()
	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		if dir == "" {
			return &ExecResult{Stdout: []byte("ruff 0.1.9")}
		}
		return &ExecResult{Stdout: []byte(`[{"code":"E501","message":"line too long","location":{"row":7,"column":1},"filename":"/project/main.py"}]`)}
	})
	linter.executor = executor

	result, err := linter.Run(context.Background(), "/project", []string{"main.py"})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, "", result.Findings[0].Suggestion)
}
