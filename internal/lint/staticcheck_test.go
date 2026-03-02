package lint

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapStaticcheckSeverity(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		severity string
		expected Severity
	}{
		{"SA code returns warning", "SA1000", "", SeverityWarning},
		{"SA code with error severity still warning", "SA2000", "error", SeverityWarning},
		{"S1 code returns info", "S1000", "", SeverityInfo},
		{"ST1 code returns info", "ST1000", "", SeverityInfo},
		{"QF code with error severity returns high", "QF1000", "error", SeverityHigh},
		{"QF code without error returns warning", "QF1000", "", SeverityWarning},
		{"Unknown code returns warning", "XX1000", "", SeverityWarning},
		{"Unknown code with error returns high", "XX1000", "error", SeverityHigh},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapStaticcheckSeverity(tt.code, tt.severity)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMapStaticcheckCategory(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		expected Category
	}{
		{"SA1000 maps to bug", "SA1000", CategoryBug},
		{"SA2000 maps to bug", "SA2000", CategoryBug},
		{"SA3000 maps to bug", "SA3000", CategoryBug},
		{"SA4000 maps to bug", "SA4000", CategoryBug},
		{"SA5000 maps to bug", "SA5000", CategoryBug},
		{"SA6000 maps to performance", "SA6000", CategoryPerformance},
		{"SA9000 maps to security", "SA9000", CategorySecurity},
		{"S1000 maps to style", "S1000", CategoryStyle},
		{"ST1000 maps to style", "ST1000", CategoryStyle},
		{"QF1000 maps to style", "QF1000", CategoryStyle},
		{"Unknown code maps to other", "XX1000", CategoryOther},
		{"Fallback unknown maps to other", "UNKNOWN", CategoryOther},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapStaticcheckCategory(tt.code)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestStaticcheck_Name(t *testing.T) {
	s := NewStaticcheck()
	assert.Equal(t, "staticcheck", s.Name())
}

func TestStaticcheck_Language(t *testing.T) {
	s := NewStaticcheck()
	assert.Equal(t, LanguageGo, s.Language())
}

func TestStaticcheckRun_ExecutionFailure(t *testing.T) {
	linter := NewStaticcheck()
	executor := NewExecutor()
	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		if dir == "" {
			return &ExecResult{Stdout: []byte("staticcheck 2024.1.1 (v0.5.1)")}
		}
		return &ExecResult{Err: errors.New("boom")}
	})
	linter.executor = executor

	result, err := linter.Run(context.Background(), "/tmp", []string{"./..."})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Errors)
}

func TestStaticcheckRun_ParseFailure(t *testing.T) {
	linter := NewStaticcheck()
	executor := NewExecutor()
	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		if dir == "" {
			return &ExecResult{Stdout: []byte("staticcheck 2024.1.1 (v0.5.1)")}
		}
		return &ExecResult{Stdout: []byte("{broken json\nnot valid")}
	})
	linter.executor = executor

	result, err := linter.Run(context.Background(), "/tmp", []string{"./..."})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Empty(t, result.Findings)
}

func TestStaticcheckRun_Success(t *testing.T) {
	linter := NewStaticcheck()
	executor := NewExecutor()
	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		if dir == "" {
			return &ExecResult{Stdout: []byte("staticcheck 2024.1.1 (v0.5.1)")}
		}
		return &ExecResult{
			ExitCode: 1,
			Stdout:   []byte(`{"code":"SA1000","severity":"warning","location":{"file":"/project/main.go","line":15,"column":2},"message":"Invalid regular expression","end":{"file":"/project/main.go","line":15,"column":20}}` + "\n"),
		}
	})
	linter.executor = executor

	result, err := linter.Run(context.Background(), "/project", []string{"./..."})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, SeverityWarning, result.Findings[0].Severity)
	assert.Equal(t, CategoryBug, result.Findings[0].Category)
	assert.Equal(t, "SA1000", result.Findings[0].Rule)
}

func TestStaticcheckExecutionError(t *testing.T) {
	tests := []struct {
		name       string
		execResult *ExecResult
		wantStop   bool
		wantText   string
	}{
		{
			name:       "exit zero succeeds",
			execResult: &ExecResult{ExitCode: 0},
			wantStop:   false,
		},
		{
			name:       "findings exit code one with output is allowed",
			execResult: &ExecResult{ExitCode: 1, Stdout: []byte(`{"code":"SA1000"}`)},
			wantStop:   false,
		},
		{
			name:       "exit code one without output is treated as failure",
			execResult: &ExecResult{ExitCode: 1, Stderr: []byte("build failed")},
			wantStop:   true,
			wantText:   "staticcheck execution failed with exit code 1: build failed",
		},
		{
			name:       "exit code greater than one is failure",
			execResult: &ExecResult{ExitCode: 2, Stderr: []byte("panic: bad input")},
			wantStop:   true,
			wantText:   "staticcheck execution failed with exit code 2: panic: bad input",
		},
		{
			name:       "explicit error is failure",
			execResult: &ExecResult{Err: errors.New("timeout")},
			wantStop:   true,
			wantText:   "staticcheck execution failed: timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, stop := staticcheckExecutionError(tt.execResult)
			assert.Equal(t, tt.wantStop, stop)
			if tt.wantStop {
				assert.Equal(t, tt.wantText, msg)
			} else {
				assert.Empty(t, msg)
			}
		})
	}
}
