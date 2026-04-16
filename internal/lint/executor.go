package lint

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lerianstudio/mithril/internal/procenv"
)

// DefaultTimeout is the default timeout for linter execution.
const DefaultTimeout = 5 * time.Minute

// maxLinterOutputBytes caps stdout+stderr per linter invocation to prevent
// unbounded memory growth if a tool goes berserk (e.g. staticcheck on a
// generated file producing one diagnostic per line for millions of lines).
// 50 MB matches the subprocess caps used elsewhere in the pipeline.
const maxLinterOutputBytes = 50 * 1024 * 1024

// ExecResult holds the result of command execution.
type ExecResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Err      error
}

// Executor runs external commands.
type Executor struct {
	timeout       time.Duration
	runFn         func(ctx context.Context, dir string, name string, args ...string) *ExecResult
	mu            sync.RWMutex
	resolvedPaths map[string]string
}

// NewExecutor creates a new command executor.
func NewExecutor() *Executor {
	return &Executor{
		timeout:       DefaultTimeout,
		resolvedPaths: make(map[string]string),
	}
}

func (e *Executor) SetRunFn(runFn func(ctx context.Context, dir string, name string, args ...string) *ExecResult) {
	e.runFn = runFn
}

// WithTimeout sets a custom timeout.
func (e *Executor) WithTimeout(d time.Duration) *Executor {
	cloned := &Executor{
		timeout:       d,
		runFn:         e.runFn,
		resolvedPaths: make(map[string]string),
	}

	e.mu.RLock()
	for name, path := range e.resolvedPaths {
		cloned.resolvedPaths[name] = path
	}
	e.mu.RUnlock()

	return cloned
}

// Run executes a command and returns the result.
func (e *Executor) Run(ctx context.Context, dir string, name string, args ...string) *ExecResult {
	if e.runFn != nil {
		result := e.runFn(ctx, dir, name, args...)
		if result == nil {
			return &ExecResult{Err: fmt.Errorf("executor runFn returned nil result")}
		}
		return result
	}

	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	cmdName := name
	if !filepath.IsAbs(name) {
		e.mu.RLock()
		resolved := e.resolvedPaths[name]
		e.mu.RUnlock()
		if resolved != "" {
			cmdName = resolved
		} else {
			resolvedPath, resolveErr := exec.LookPath(name)
			if resolveErr != nil {
				return &ExecResult{Err: fmt.Errorf("command not found: %w", resolveErr)}
			}
			cmdName = resolvedPath
			e.mu.Lock()
			if e.resolvedPaths == nil {
				e.resolvedPaths = make(map[string]string)
			}
			e.resolvedPaths[name] = resolvedPath
			e.mu.Unlock()
		}
	}

	cmd := exec.Command(cmdName, args...) // #nosec G204 - name/args come from registered linters
	cmd.Dir = dir
	cmd.Env = procenv.Build()
	configureProcessGroup(cmd)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &cappedWriter{w: &stdout, limit: maxLinterOutputBytes}
	cmd.Stderr = &cappedWriter{w: &stderr, limit: maxLinterOutputBytes}

	if err := cmd.Start(); err != nil {
		return &ExecResult{Err: err}
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		terminateProcess(cmd)
		err = <-done
	}

	result := &ExecResult{
		Stdout: stdout.Bytes(),
		Stderr: stderr.Bytes(),
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			result.Err = fmt.Errorf("command timed out after %v", e.timeout)
			return result
		}

		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
			// Many linters return non-zero on findings, which is not an error.
			result.Err = nil
		} else {
			result.Err = err
		}
	}

	return result
}

// cappedWriter bounds the number of bytes forwarded to the underlying writer
// so a runaway linter cannot exhaust memory. Writes past the limit are
// silently discarded; callers may detect truncation via wrote >= limit.
type cappedWriter struct {
	w     *bytes.Buffer
	limit int
	wrote int
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	remaining := c.limit - c.wrote
	if remaining <= 0 {
		// Pretend the full write succeeded so the child process doesn't
		// get SIGPIPE from stdout; we just drop the overflow.
		return len(p), nil
	}
	n := len(p)
	if n > remaining {
		_, err := c.w.Write(p[:remaining])
		c.wrote += remaining
		return n, err
	}
	_, err := c.w.Write(p)
	c.wrote += n
	return n, err
}

// CommandAvailable checks if a command is available in PATH.
func (e *Executor) CommandAvailable(ctx context.Context, name string) bool {
	if ctx.Err() != nil {
		return false
	}

	path, err := exec.LookPath(name)
	if err != nil {
		return false
	}
	if ctx.Err() != nil {
		return false
	}

	e.mu.Lock()
	if e.resolvedPaths == nil {
		e.resolvedPaths = make(map[string]string)
	}
	e.resolvedPaths[name] = path
	e.mu.Unlock()

	return true
}

// GetVersion runs a command with --version and extracts the version string.
func (e *Executor) GetVersion(ctx context.Context, name string, args ...string) (string, error) {
	if len(args) == 0 {
		args = []string{"--version"}
	}

	result := e.Run(ctx, "", name, args...)
	if result.Err != nil {
		return "", result.Err
	}

	output := string(result.Stdout)
	if output == "" {
		output = string(result.Stderr)
	}

	// Extract first line and clean up
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) > 0 {
		return strings.TrimSpace(lines[0]), nil
	}

	return "unknown", nil
}
