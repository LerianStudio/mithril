package procenv

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"time"
)

// DefaultHelperTimeout is the default wall-clock cap for helper subprocesses
// (python3, node, npx) that produce JSON. It matches callgraph's 120s budget.
const DefaultHelperTimeout = 120 * time.Second

// DefaultMaxHelperOutput caps helper stdout at 50 MB. Large enough for real
// workloads, small enough to bound memory on pathological input.
const DefaultMaxHelperOutput = 50 * 1024 * 1024

// OutputTooLargeError is returned when a helper's stdout exceeds the limit.
type OutputTooLargeError struct {
	Size  int
	Limit int
}

func (e *OutputTooLargeError) Error() string {
	return fmt.Sprintf("helper output exceeds size limit (%d > %d bytes)", e.Size, e.Limit)
}

// RunHelper executes an external helper (python3, node, npx, etc.) with the
// given args. Stdout is captured up to maxOutput bytes; stderr is attached to
// any *exec.ExitError. If ctx has no deadline, DefaultHelperTimeout is applied.
// If maxOutput <= 0, DefaultMaxHelperOutput is used.
//
// The returned environment is always sanitized via Build().
func RunHelper(ctx context.Context, workDir, command string, args []string, maxOutput int) ([]byte, error) {
	if maxOutput <= 0 {
		maxOutput = DefaultMaxHelperOutput
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultHelperTimeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, command, args...) // #nosec G204 - callers sanitize args
	cmd.Dir = workDir
	cmd.Env = Build()

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	output, readErr := io.ReadAll(io.LimitReader(stdout, int64(maxOutput)+1))
	if readErr != nil {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
		return nil, fmt.Errorf("failed to read helper output: %w", readErr)
	}

	if len(output) > maxOutput {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
		return nil, &OutputTooLargeError{Size: len(output), Limit: maxOutput}
	}

	waitErr := cmd.Wait()
	if exitErr, ok := waitErr.(*exec.ExitError); ok {
		exitErr.Stderr = stderr.Bytes()
	}
	if waitErr != nil {
		return nil, waitErr
	}

	return output, nil
}
