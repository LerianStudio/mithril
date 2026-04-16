package lint

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordToolVersion_Success(t *testing.T) {
	r := NewResult()
	ok := recordToolVersion(context.Background(), r, "foo", func(ctx context.Context) (string, error) {
		return "1.2.3", nil
	})
	require.True(t, ok)
	assert.Equal(t, "1.2.3", r.ToolVersions["foo"])
	assert.Empty(t, r.Errors)
}

func TestRecordToolVersion_Failure(t *testing.T) {
	r := NewResult()
	ok := recordToolVersion(context.Background(), r, "foo", func(ctx context.Context) (string, error) {
		return "", errors.New("boom")
	})
	require.False(t, ok)
	assert.Empty(t, r.ToolVersions)
	require.Len(t, r.Errors, 1)
	assert.Contains(t, r.Errors[0], "foo version check failed")
}

func TestAppendValidationError_Invalid(t *testing.T) {
	r := NewResult()
	ok := appendValidationError(r, "tool", []string{"--fix"})
	require.False(t, ok)
	require.Len(t, r.Errors, 1)
	assert.Contains(t, r.Errors[0], "tool target validation failed")
}

func TestAppendValidationError_Valid(t *testing.T) {
	r := NewResult()
	ok := appendValidationError(r, "tool", []string{"src/main.go"})
	require.True(t, ok)
	assert.Empty(t, r.Errors)
}

func TestAppendExecError(t *testing.T) {
	r := NewResult()
	appendExecError(r, "tool", errors.New("bad"))
	require.Len(t, r.Errors, 1)
	assert.Contains(t, r.Errors[0], "tool execution failed")
	assert.Contains(t, r.Errors[0], "bad")
}

func TestAppendParseError(t *testing.T) {
	r := NewResult()
	appendParseError(r, "tool", errors.New("json"))
	require.Len(t, r.Errors, 1)
	assert.Contains(t, r.Errors[0], "tool output parse warning")
}
