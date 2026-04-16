package callgraph

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/lerianstudio/mithril/internal/procenv"
)

// maxHelperOutputSize caps subprocess stdout at 50 MB. Both the Python and
// TypeScript call-graph helpers share this limit; it is large enough to hold
// realistic helper output but small enough to bound memory for pathological
// cases (see H34 dedup note).
const maxHelperOutputSize = 50 * 1024 * 1024

// outputTooLargeError is returned when a helper's stdout exceeds
// maxHelperOutputSize bytes. Callers use errors.As to distinguish this from
// generic subprocess failures so they can short-circuit fallbacks.
type outputTooLargeError struct {
	size  int
	limit int
}

func (e *outputTooLargeError) Error() string {
	return fmt.Sprintf("helper output exceeds size limit (%d > %d bytes)", e.size, e.limit)
}

// runHelperCommand executes an external helper (python3, node, npx, etc.) with
// the given args, capturing stdout up to maxHelperOutputSize. Stderr is
// attached to any *exec.ExitError so callers preserve the usual
// Cmd.Output() behavior. The child is killed and reaped if stdout exceeds the
// size limit to prevent memory blow-up.
func runHelperCommand(ctx context.Context, workDir, command string, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, command, args...) // #nosec G204 - callers sanitize args
	cmd.Dir = workDir
	cmd.Env = procenv.Build()

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	output, readErr := io.ReadAll(io.LimitReader(stdout, maxHelperOutputSize+1))
	if readErr != nil {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
		return nil, fmt.Errorf("failed to read helper output: %w", readErr)
	}

	if len(output) > maxHelperOutputSize {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
		return nil, &outputTooLargeError{size: len(output), limit: maxHelperOutputSize}
	}

	waitErr := cmd.Wait()
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		exitErr.Stderr = stderr.Bytes()
	}
	if waitErr != nil {
		return nil, waitErr
	}

	return output, nil
}

// sanitizeHelperFilePaths validates that every path in files is safe to pass
// to an external helper subprocess: not a flag (no leading dash), contains no
// null bytes, resolves to an existing location, and lives within workDir
// after symlink evaluation. The caller's original strings are returned (not
// the resolved absolute paths) so helper scripts see paths relative to
// workDir where possible.
func sanitizeHelperFilePaths(workDir string, files []string) ([]string, error) {
	absWorkDir, err := filepath.Abs(workDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve workDir: %w", err)
	}
	realWorkDir, err := filepath.EvalSymlinks(absWorkDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve workDir symlinks: %w", err)
	}

	sanitized := make([]string, 0, len(files))
	for _, f := range files {
		if strings.HasPrefix(f, "-") {
			return nil, fmt.Errorf("invalid file path (starts with dash): %s", f)
		}
		if strings.ContainsRune(f, '\x00') {
			return nil, fmt.Errorf("invalid file path (contains null byte)")
		}

		absPath, absErr := filepath.Abs(f)
		if absErr != nil {
			return nil, fmt.Errorf("invalid file path (cannot resolve): %s", f)
		}

		realPath, evalErr := filepath.EvalSymlinks(absPath)
		if evalErr != nil {
			return nil, fmt.Errorf("invalid file path (cannot resolve symlinks): %s", f)
		}

		if !strings.HasPrefix(realPath, realWorkDir+string(filepath.Separator)) && realPath != realWorkDir {
			return nil, fmt.Errorf("invalid file path (outside work directory): %s", f)
		}

		sanitized = append(sanitized, f)
	}
	return sanitized, nil
}

// collectUniqueFiles returns the de-duplicated set of file paths referenced by
// the given modified functions, preserving first-seen order.
func collectUniqueFiles(funcs []ModifiedFunction) []string {
	seen := make(map[string]bool, len(funcs))
	files := make([]string, 0, len(funcs))

	for _, fn := range funcs {
		if fn.File == "" || seen[fn.File] {
			continue
		}
		seen[fn.File] = true
		files = append(files, fn.File)
	}

	return files
}

// affectedPackages returns the de-duplicated list of packages (or directories,
// for languages without an explicit Package field) touched by the given
// modified functions, preserving first-seen order.
func affectedPackages(funcs []ModifiedFunction) []string {
	seen := make(map[string]bool, len(funcs))
	pkgs := make([]string, 0, len(funcs))

	for _, fn := range funcs {
		pkg := fn.Package
		if pkg == "" {
			pkg = filepath.Dir(fn.File)
		}
		if pkg == "" || seen[pkg] {
			continue
		}
		seen[pkg] = true
		pkgs = append(pkgs, pkg)
	}

	return pkgs
}
