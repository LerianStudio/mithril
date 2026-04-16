// Package fileutil provides shared file utilities for codereview tools.
package fileutil

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// MaxJSONFileSize is the maximum allowed size for JSON files (50MB).
const MaxJSONFileSize = 50 * 1024 * 1024

// ValidateRelativePath ensures a path is relative and does not escape the working directory.
// Returns the cleaned relative path when valid.
func ValidateRelativePath(path string) (string, error) {
	cleanPath := filepath.Clean(path)
	if filepath.IsAbs(cleanPath) {
		return "", fmt.Errorf("path must be relative: %s", path)
	}
	if strings.HasPrefix(cleanPath, ".."+string(filepath.Separator)) || cleanPath == ".." {
		return "", fmt.Errorf("path contains directory traversal: %s", path)
	}
	return cleanPath, nil
}

// ValidatePath ensures a path does not escape the working directory.
// Relative paths are normalized; absolute paths are allowed but must not escape workDir.
//
// workDir must be non-empty. Pass "." to opt into the permissive mode that
// accepts absolute paths regardless of containment (used by callers that
// legitimately consume paths supplied via CLI flags). An empty workDir is
// rejected to prevent silently allowing arbitrary absolute paths.
func ValidatePath(path string, workDir string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path cannot be empty")
	}
	if workDir == "" {
		return "", fmt.Errorf("workDir cannot be empty; pass \".\" to allow absolute paths explicitly")
	}

	baseAbs, err := filepath.Abs(workDir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve working directory: %w", err)
	}

	cleaned := filepath.Clean(path)
	if filepath.IsAbs(cleaned) {
		if workDir != "." {
			if !strings.HasPrefix(cleaned, baseAbs+string(filepath.Separator)) && cleaned != baseAbs {
				return "", fmt.Errorf("path escapes working directory: %s", path)
			}
		}
		return cleaned, nil
	}
	if strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) || cleaned == ".." {
		return "", fmt.Errorf("path contains directory traversal: %s", path)
	}
	absPath := filepath.Join(baseAbs, cleaned)
	if workDir != "." {
		if !strings.HasPrefix(absPath, baseAbs+string(filepath.Separator)) && absPath != baseAbs {
			return "", fmt.Errorf("path escapes working directory: %s", path)
		}
	}
	return absPath, nil
}

// ReadJSONFileWithLimit reads a JSON file with size validation to prevent resource exhaustion.
// It validates the path to prevent directory traversal attacks. Absolute paths
// are accepted (many callers receive user-supplied CLI paths).
func ReadJSONFileWithLimit(path string) ([]byte, error) {
	// Normalize path. We pass "." (permissive mode) because this helper is
	// commonly called with absolute paths taken from CLI flags. Callers that
	// need containment must validate the path themselves first via
	// ValidatePath(path, workDir) with a non-empty workDir.
	cleanPath, err := ValidatePath(path, ".")
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	if info.Size() > MaxJSONFileSize {
		return nil, fmt.Errorf("file %s exceeds maximum allowed size of %d bytes (actual: %d bytes)", cleanPath, MaxJSONFileSize, info.Size())
	}

	return os.ReadFile(cleanPath) // #nosec G304 - path is validated against traversal
}

// writeJSONOptions holds tunable behaviour for WriteJSONFile.
type writeJSONOptions struct {
	perm          os.FileMode
	indent        string
	prefix        string
	trailingNL    bool
	atomic        bool
	refuseSymlink bool
}

// WriteJSONOption tunes WriteJSONFile behaviour. Defaults are set to
// safe production values (0o600, two-space indent, trailing newline,
// atomic write via tmpfile + rename, symlink refusal).
type WriteJSONOption func(*writeJSONOptions)

// WithPerm overrides the file permission (default 0o600).
func WithPerm(perm os.FileMode) WriteJSONOption {
	return func(o *writeJSONOptions) { o.perm = perm }
}

// WithIndent overrides MarshalIndent indent (default "  ").
func WithIndent(indent string) WriteJSONOption {
	return func(o *writeJSONOptions) { o.indent = indent }
}

// WithTrailingNewline toggles the trailing "\n" after JSON output (default true).
func WithTrailingNewline(trailing bool) WriteJSONOption {
	return func(o *writeJSONOptions) { o.trailingNL = trailing }
}

// WithAtomicWrite toggles write-to-tmpfile-then-rename (default true).
// When false, WriteJSONFile writes directly to the destination path.
func WithAtomicWrite(atomic bool) WriteJSONOption {
	return func(o *writeJSONOptions) { o.atomic = atomic }
}

// WithSymlinkRefusal toggles refusing to write to existing symlink targets (default true).
func WithSymlinkRefusal(refuse bool) WriteJSONOption {
	return func(o *writeJSONOptions) { o.refuseSymlink = refuse }
}

// WriteJSONFile marshals v as pretty-printed JSON and writes it to path.
// Default behaviour: 0o600 perms, 2-space indent, trailing newline,
// atomic write (tmpfile + rename in the same directory), and refusal to
// overwrite an existing symlink target. Parent directories are created
// with 0o700 perms if missing. Options override the defaults.
//
// This is the canonical helper for persisting analysis outputs. Call
// sites that inline json.MarshalIndent + os.WriteFile should migrate
// here so permissions, newlines, and symlink safety stay consistent.
func WriteJSONFile(path string, v any, opts ...WriteJSONOption) error {
	options := &writeJSONOptions{
		perm:          0o600,
		indent:        "  ",
		prefix:        "",
		trailingNL:    true,
		atomic:        true,
		refuseSymlink: true,
	}
	for _, opt := range opts {
		opt(options)
	}

	if options.refuseSymlink {
		if info, err := os.Lstat(path); err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("refusing to write to symlink path: %s", path)
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("failed to stat output path %s: %w", path, err)
		}
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	payload, err := json.MarshalIndent(v, options.prefix, options.indent)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON for %s: %w", path, err)
	}
	if options.trailingNL && (len(payload) == 0 || payload[len(payload)-1] != '\n') {
		payload = append(payload, '\n')
	}

	if !options.atomic {
		if err := os.WriteFile(path, payload, options.perm); err != nil {
			return fmt.Errorf("failed to write file %s: %w", path, err)
		}
		return nil
	}

	tmp, err := os.CreateTemp(dir, ".writejson-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	// On any failure after CreateTemp, best-effort cleanup of the tmp file.
	cleanup := func() { _ = os.Remove(tmpPath) }

	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("failed to write temp file %s: %w", tmpPath, err)
	}
	if err := tmp.Chmod(options.perm); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("failed to chmod temp file %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("failed to close temp file %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("failed to rename %s -> %s: %w", tmpPath, path, err)
	}
	return nil
}

// ValidateDirectory ensures a directory exists and does not escape the working directory.
func ValidateDirectory(path string, workDir string) (string, error) {
	cleanPath, err := ValidatePath(path, workDir)
	if err != nil {
		return "", err
	}

	info, err := os.Stat(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("directory does not exist: %s", cleanPath)
		}
		return "", fmt.Errorf("failed to stat directory: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("path is not a directory: %s", cleanPath)
	}

	return cleanPath, nil
}
