package lint

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestExecutorRun_ExitCodeFromLinterFindings(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell command differs on windows")
	}

	executor := NewExecutor()
	result := executor.Run(context.Background(), "", "sh", "-c", "exit 2")

	require.NotNil(t, result)
	require.NoError(t, result.Err)
	require.Equal(t, 2, result.ExitCode)
}

func TestExecutorRun_Timeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell command differs on windows")
	}

	executor := NewExecutor().WithTimeout(50 * time.Millisecond)
	result := executor.Run(context.Background(), "", "sh", "-c", "sleep 2")

	require.NotNil(t, result)
	require.Error(t, result.Err)
	require.Contains(t, result.Err.Error(), "timed out")
}

func TestExecutorRun_CommandNotFound(t *testing.T) {
	executor := NewExecutor()
	result := executor.Run(context.Background(), "", "definitely-not-a-real-command-xyz")

	require.NotNil(t, result)
	require.Error(t, result.Err)
}

func TestExecutorGetVersion_FallbackToStderr(t *testing.T) {
	executor := NewExecutor()
	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		return &ExecResult{Stdout: []byte{}, Stderr: []byte("v1.2.3\n"), ExitCode: 0}
	})

	version, err := executor.GetVersion(context.Background(), "tool")
	require.NoError(t, err)
	require.Equal(t, "v1.2.3", version)
}

func TestExecutorCommandAvailable_CancelledContext(t *testing.T) {
	executor := NewExecutor()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	available := executor.CommandAvailable(ctx, "go")
	require.False(t, available)
}

func TestExecutorWithTimeout_CopySemantics(t *testing.T) {
	original := NewExecutor()
	copy := original.WithTimeout(time.Second)

	require.NotSame(t, original, copy)
	require.Equal(t, DefaultTimeout, original.timeout)
	require.Equal(t, time.Second, copy.timeout)
}

func TestExecutorRun_UsesCachedResolvedPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("path and executable semantics differ on windows")
	}

	tempDir := t.TempDir()
	cmdPath := filepath.Join(tempDir, "mockcmd")
	if err := os.WriteFile(cmdPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("failed to create mock command: %v", err)
	}

	originalPath := os.Getenv("PATH")
	t.Cleanup(func() {
		if err := os.Setenv("PATH", originalPath); err != nil {
			t.Errorf("failed to restore PATH: %v", err)
		}
	})

	if err := os.Setenv("PATH", tempDir); err != nil {
		t.Fatalf("failed to set PATH: %v", err)
	}

	executor := NewExecutor()
	require.True(t, executor.CommandAvailable(context.Background(), "mockcmd"))

	if err := os.Setenv("PATH", ""); err != nil {
		t.Fatalf("failed to clear PATH: %v", err)
	}

	result := executor.Run(context.Background(), "", "mockcmd")
	require.NotNil(t, result)
	require.NoError(t, result.Err)
	if result.ExitCode != 0 {
		t.Fatalf("expected cached command to execute successfully, got exit code %d", result.ExitCode)
	}
}

func TestExecutorRun_RunFnReturningNilIsHandled(t *testing.T) {
	executor := NewExecutor()
	executor.SetRunFn(func(ctx context.Context, dir string, name string, args ...string) *ExecResult {
		return nil
	})

	result := executor.Run(context.Background(), "", "go", "version")
	require.NotNil(t, result)
	require.Error(t, result.Err)
	require.Contains(t, result.Err.Error(), "runFn returned nil")
}
