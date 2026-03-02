package lint

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapGosecSeverity(t *testing.T) {
	tests := []struct {
		name       string
		severity   string
		confidence string
		expected   Severity
	}{
		{"HIGH severity HIGH confidence returns critical", "HIGH", "HIGH", SeverityCritical},
		{"HIGH severity MEDIUM confidence returns high", "HIGH", "MEDIUM", SeverityHigh},
		{"HIGH severity LOW confidence returns high", "HIGH", "LOW", SeverityHigh},
		{"MEDIUM severity HIGH confidence returns warning", "MEDIUM", "HIGH", SeverityWarning},
		{"MEDIUM severity MEDIUM confidence returns warning", "MEDIUM", "MEDIUM", SeverityWarning},
		{"LOW severity HIGH confidence returns info", "LOW", "HIGH", SeverityInfo},
		{"LOW severity LOW confidence returns info", "LOW", "LOW", SeverityInfo},
		{"lowercase high high returns critical", "high", "high", SeverityCritical},
		{"mixed case returns correct severity", "High", "Medium", SeverityHigh},
		{"empty severity returns info", "", "HIGH", SeverityInfo},
		{"empty confidence returns appropriate severity", "HIGH", "", SeverityHigh},
		{"empty severity and confidence returns info", "", "", SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapGosecSeverity(tt.severity, tt.confidence)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGosec_Name(t *testing.T) {
	g := NewGosec()
	assert.Equal(t, "gosec", g.Name())
}

func TestGosec_Language(t *testing.T) {
	g := NewGosec()
	assert.Equal(t, LanguageGo, g.Language())
}

func TestGosecRun_ExecutionFailure(t *testing.T) {
	linter := NewGosec()
	executor := NewExecutor()
	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		if dir == "" {
			return &ExecResult{Stdout: []byte("Version: 2.18.0")}
		}
		return &ExecResult{Err: errors.New("boom")}
	})
	linter.executor = executor

	result, err := linter.Run(context.Background(), "/tmp", []string{"./..."})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Errors)
}

func TestGosecRun_ParseFailure(t *testing.T) {
	linter := NewGosec()
	executor := NewExecutor()
	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		if dir == "" {
			return &ExecResult{Stdout: []byte("Version: 2.18.0")}
		}
		return &ExecResult{Stdout: []byte("{broken")}
	})
	linter.executor = executor

	result, err := linter.Run(context.Background(), "/tmp", []string{"./..."})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Errors)
	assert.Empty(t, result.Findings)
}

func TestGosecRun_Success(t *testing.T) {
	linter := NewGosec()
	executor := NewExecutor()
	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		if dir == "" {
			return &ExecResult{Stdout: []byte("Version: 2.18.0")}
		}
		return &ExecResult{Stdout: []byte(`{"Issues":[{"severity":"HIGH","confidence":"HIGH","rule_id":"G101","details":"Potential hardcoded credentials","file":"/project/config.go","line":"42","column":"5","code":"password := \"secret\""}]}`)}
	})
	linter.executor = executor

	result, err := linter.Run(context.Background(), "/project", []string{"./..."})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, SeverityCritical, result.Findings[0].Severity)
	assert.Equal(t, CategorySecurity, result.Findings[0].Category)
	assert.Equal(t, "G101", result.Findings[0].Rule)
}

func TestGosecRun_ParsesLineAndColumnRanges(t *testing.T) {
	linter := NewGosec()
	executor := NewExecutor()
	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		if dir == "" {
			return &ExecResult{Stdout: []byte("Version: 2.18.0")}
		}
		return &ExecResult{Stdout: []byte(`{"Issues":[{"severity":"HIGH","confidence":"HIGH","rule_id":"G201","details":"SQL query construction","file":"/project/db.go","line":"12-18","column":"7-12","code":"query := ..."}]}`)}
	})
	linter.executor = executor

	result, err := linter.Run(context.Background(), "/project", []string{"./..."})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, 12, result.Findings[0].Line)
	assert.Equal(t, 7, result.Findings[0].Column)
}
