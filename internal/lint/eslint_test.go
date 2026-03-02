package lint

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapESLintSeverity(t *testing.T) {
	tests := []struct {
		input    int
		expected Severity
	}{
		{2, SeverityHigh},
		{1, SeverityWarning},
		{0, SeverityInfo},
		{99, SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("severity_%d", tt.input), func(t *testing.T) {
			result := mapESLintSeverity(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMapESLintCategory(t *testing.T) {
	tests := []struct {
		ruleID   string
		expected Category
	}{
		{"@typescript-eslint/no-unused-vars", CategoryType},
		{"@typescript-eslint/explicit-function-return-type", CategoryType},
		{"security/detect-object-injection", CategorySecurity},
		{"no-unused-vars", CategoryUnused},
		{"no-unused-expressions", CategoryUnused},
		{"import/order", CategoryStyle},
		{"import/no-unresolved", CategoryStyle},
		{"react/jsx-uses-react", CategoryStyle},
		{"react-hooks/rules-of-hooks", CategoryStyle},
		{"parse-error", CategoryBug},
		{"semi", CategoryStyle},
		{"unknown-rule", CategoryStyle},
	}

	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			result := mapESLintCategory(tt.ruleID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestESLint_Name(t *testing.T) {
	e := NewESLint()
	assert.Equal(t, "eslint", e.Name())
}

func TestESLint_Language(t *testing.T) {
	e := NewESLint()
	assert.Equal(t, LanguageTypeScript, e.Language())
}

func TestESLintRun_ExecutionFailure(t *testing.T) {
	linter := NewESLint()
	executor := NewExecutor()
	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		if dir == "" {
			return &ExecResult{Stdout: []byte("v8.56.0")}
		}
		return &ExecResult{Err: errors.New("boom"), ExitCode: 2}
	})
	linter.executor = executor

	result, err := linter.Run(context.Background(), "/tmp", []string{"src/index.ts"})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotEmpty(t, result.Errors)
	assert.Contains(t, result.Errors[0], "eslint execution failed")
}

func TestESLintRun_ParseFailure(t *testing.T) {
	linter := NewESLint()
	executor := NewExecutor()
	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		if dir == "" {
			return &ExecResult{Stdout: []byte("v8.56.0")}
		}
		return &ExecResult{Stdout: []byte("{broken")}
	})
	linter.executor = executor

	result, err := linter.Run(context.Background(), "/tmp", []string{"src/index.ts"})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotEmpty(t, result.Errors)
	assert.Contains(t, result.Errors[0], "eslint output parse warning")
	assert.Empty(t, result.Findings)
}

func TestESLintRun_Success(t *testing.T) {
	linter := NewESLint()
	executor := NewExecutor()
	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		if dir == "" {
			return &ExecResult{Stdout: []byte("v8.56.0")}
		}
		return &ExecResult{Stdout: []byte(`[{"filePath":"/project/src/index.ts","messages":[{"ruleId":"no-unused-vars","severity":1,"message":"'x' is defined but never used","line":10,"column":7}]}]`)}
	})
	linter.executor = executor

	result, err := linter.Run(context.Background(), "/project", []string{"src/index.ts"})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, SeverityWarning, result.Findings[0].Severity)
	assert.Equal(t, CategoryUnused, result.Findings[0].Category)
	assert.Equal(t, "no-unused-vars", result.Findings[0].Rule)
}
