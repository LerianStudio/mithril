package lint

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapBanditSeverity(t *testing.T) {
	tests := []struct {
		name       string
		severity   string
		confidence string
		expected   Severity
	}{
		{"HIGH severity HIGH confidence returns critical", "HIGH", "HIGH", SeverityCritical},
		{"HIGH severity MEDIUM confidence returns high", "HIGH", "MEDIUM", SeverityHigh},
		{"HIGH severity LOW confidence returns high", "HIGH", "LOW", SeverityHigh},
		{"HIGH severity empty confidence returns high", "HIGH", "", SeverityHigh},
		{"MEDIUM severity HIGH confidence returns warning", "MEDIUM", "HIGH", SeverityWarning},
		{"MEDIUM severity MEDIUM confidence returns warning", "MEDIUM", "MEDIUM", SeverityWarning},
		{"MEDIUM severity LOW confidence returns warning", "MEDIUM", "LOW", SeverityWarning},
		{"LOW severity HIGH confidence returns info", "LOW", "HIGH", SeverityInfo},
		{"LOW severity MEDIUM confidence returns info", "LOW", "MEDIUM", SeverityInfo},
		{"LOW severity LOW confidence returns info", "LOW", "LOW", SeverityInfo},
		{"lowercase high high returns critical", "high", "high", SeverityCritical},
		{"mixed case returns correct severity", "High", "Medium", SeverityHigh},
		{"empty severity returns info", "", "HIGH", SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapBanditSeverity(tt.severity, tt.confidence)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBandit_Name(t *testing.T) {
	b := NewBandit()
	assert.Equal(t, "bandit", b.Name())
}

func TestBandit_Language(t *testing.T) {
	b := NewBandit()
	assert.Equal(t, LanguagePython, b.Language())
}

func TestBanditRun_ExecutionFailure(t *testing.T) {
	linter := NewBandit()
	executor := NewExecutor()
	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		if dir == "" {
			return &ExecResult{Stdout: []byte("bandit 1.7.7")}
		}
		return &ExecResult{Err: errors.New("boom")}
	})
	linter.executor = executor

	result, err := linter.Run(context.Background(), "/tmp", []string{"main.py"})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotEmpty(t, result.Errors)
	assert.Contains(t, result.Errors[0], "bandit execution failed")
}

func TestBanditRun_ParseFailure(t *testing.T) {
	linter := NewBandit()
	executor := NewExecutor()
	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		if dir == "" {
			return &ExecResult{Stdout: []byte("bandit 1.7.7")}
		}
		return &ExecResult{Stdout: []byte("{broken")}
	})
	linter.executor = executor

	result, err := linter.Run(context.Background(), "/tmp", []string{"main.py"})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotEmpty(t, result.Errors)
	assert.Contains(t, result.Errors[0], "bandit output parse warning")
	assert.Empty(t, result.Findings)
}

func TestBanditRun_Success(t *testing.T) {
	linter := NewBandit()
	executor := NewExecutor()
	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		if dir == "" {
			return &ExecResult{Stdout: []byte("bandit 1.7.7")}
		}
		return &ExecResult{Stdout: []byte(`{"results":[{"code":"import subprocess\nsubprocess.call(cmd, shell=True)\n","filename":"/project/main.py","issue_text":"subprocess call with shell=True","issue_severity":"HIGH","issue_confidence":"HIGH","line_number":5,"line_range":[5,6],"more_info":"https://bandit.readthedocs.io/en/latest/plugins/b602.html","test_id":"B602","test_name":"subprocess_popen_with_shell_equals_true"}],"metrics":{"issues":1}}`)}
	})
	linter.executor = executor

	result, err := linter.Run(context.Background(), "/project", []string{"main.py"})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, SeverityCritical, result.Findings[0].Severity)
	assert.Equal(t, CategorySecurity, result.Findings[0].Category)
	assert.Equal(t, "B602", result.Findings[0].Rule)
}
