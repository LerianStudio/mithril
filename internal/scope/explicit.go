package scope

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lerianstudio/mithril/internal/git"
)

// DetectFromFiles analyzes an explicit file list (with optional base ref) for scope.
func (d *Detector) DetectFromFiles(baseRef string, files []string) (*ScopeResult, error) {
	if len(files) == 0 {
		return nil, fmt.Errorf("no files provided")
	}

	cleanFiles := normalizeFileList(files)
	if len(cleanFiles) == 0 {
		return nil, fmt.Errorf("no valid files provided")
	}

	if baseRef == "" {
		baseRef = "HEAD"
	}

	return d.buildScopeResultFromFiles(baseRef, cleanFiles)
}

// errFileRaceMissing signals that a file disappeared from both the base ref
// and the working tree between the time it was listed and the time its
// status was resolved — a benign race (IDE save, concurrent git op) the
// caller should skip rather than treat as fatal.
var errFileRaceMissing = errors.New("file not found in base or working tree")

func resolveFileStatus(client gitClientInterface, workDir, baseRef, file string) (git.FileStatus, error) {
	if baseRef == "" {
		baseRef = "HEAD"
	}

	inBase, err := client.FileExistsAtRef(baseRef, file)
	if err != nil {
		return git.StatusUnknown, err
	}

	inWorktree, err := fileExistsInWorkdir(workDir, file)
	if err != nil {
		return git.StatusUnknown, err
	}

	switch {
	case inBase && inWorktree:
		return git.StatusModified, nil
	case inBase && !inWorktree:
		return git.StatusDeleted, nil
	case !inBase && inWorktree:
		return git.StatusAdded, nil
	default:
		return git.StatusUnknown, fmt.Errorf("%w: %s", errFileRaceMissing, file)
	}
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// fileExistsInWorkdir checks whether `file` exists under `workDir`, resolving
// any symlinks and verifying the resolved path is still contained inside
// workDir. Files that resolve outside the workdir are treated as non-existent
// so that a symlink attack (foo.txt -> /etc/shadow) cannot let an attacker
// pull arbitrary files into the analysis pipeline.
func fileExistsInWorkdir(workDir, file string) (bool, error) {
	if workDir == "" {
		return fileExists(file)
	}
	joined := filepath.Join(workDir, file)

	if _, err := os.Lstat(joined); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}

	baseAbs, err := filepath.Abs(workDir)
	if err != nil {
		return false, err
	}
	baseReal, err := filepath.EvalSymlinks(baseAbs)
	if err != nil {
		// If the workdir itself can't be resolved, fall back to the abs form.
		baseReal = baseAbs
	}

	resolved, err := filepath.EvalSymlinks(joined)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	resolvedAbs, err := filepath.Abs(resolved)
	if err != nil {
		return false, err
	}

	sep := string(filepath.Separator)
	if resolvedAbs != baseReal && !strings.HasPrefix(resolvedAbs, baseReal+sep) {
		return false, fmt.Errorf("file %q resolves outside working directory", file)
	}
	return true, nil
}

func findFileStats(statsByFile map[string]git.FileStats, file string) git.FileStats {
	if len(statsByFile) == 0 {
		return git.FileStats{}
	}
	if stats, ok := statsByFile[file]; ok {
		return stats
	}
	cleaned := filepath.Clean(file)
	for path, stats := range statsByFile {
		if filepath.Clean(path) == cleaned {
			return stats
		}
	}
	return git.FileStats{}
}

func normalizeFileList(files []string) []string {
	result := make([]string, 0, len(files))
	seen := make(map[string]bool)
	for _, file := range files {
		if file == "" {
			continue
		}
		cleaned := filepath.Clean(file)
		if cleaned == "." {
			continue
		}
		if !seen[cleaned] {
			seen[cleaned] = true
			result = append(result, cleaned)
		}
	}
	return result
}
