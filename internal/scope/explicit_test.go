package scope

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/lerianstudio/mithril/internal/git"
)

func TestResolveFileStatus(t *testing.T) {
	workDir := t.TempDir()
	fileName := "test.go"
	filePath := filepath.Join(workDir, fileName)

	writeFile := func() {
		if err := os.WriteFile(filePath, []byte("package main\n"), 0o644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}
	}

	removeFile := func() {
		if err := os.Remove(filePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed to remove test file: %v", err)
		}
	}

	t.Run("modified", func(t *testing.T) {
		writeFile()
		client := &mockGitClient{fileExists: map[string]bool{fileName: true}}
		status, err := resolveFileStatus(client, workDir, "HEAD", fileName)
		if err != nil {
			t.Fatalf("resolveFileStatus returned error: %v", err)
		}
		if status != git.StatusModified {
			t.Fatalf("status = %s, want %s", status, git.StatusModified)
		}
	})

	t.Run("deleted", func(t *testing.T) {
		removeFile()
		client := &mockGitClient{fileExists: map[string]bool{fileName: true}}
		status, err := resolveFileStatus(client, workDir, "HEAD", fileName)
		if err != nil {
			t.Fatalf("resolveFileStatus returned error: %v", err)
		}
		if status != git.StatusDeleted {
			t.Fatalf("status = %s, want %s", status, git.StatusDeleted)
		}
	})

	t.Run("added", func(t *testing.T) {
		writeFile()
		client := &mockGitClient{fileExists: map[string]bool{fileName: false}}
		status, err := resolveFileStatus(client, workDir, "HEAD", fileName)
		if err != nil {
			t.Fatalf("resolveFileStatus returned error: %v", err)
		}
		if status != git.StatusAdded {
			t.Fatalf("status = %s, want %s", status, git.StatusAdded)
		}
	})

	t.Run("unknown", func(t *testing.T) {
		removeFile()
		client := &mockGitClient{fileExists: map[string]bool{fileName: false}}
		status, err := resolveFileStatus(client, workDir, "HEAD", fileName)
		if err == nil {
			t.Fatal("expected error for file missing in base and worktree")
		}
		if status != git.StatusUnknown {
			t.Fatalf("status = %s, want %s", status, git.StatusUnknown)
		}
	})

	t.Run("git error", func(t *testing.T) {
		writeFile()
		client := &mockGitClient{fileExistsErr: errors.New("git failure")}
		status, err := resolveFileStatus(client, workDir, "HEAD", fileName)
		if err == nil {
			t.Fatal("expected git error")
		}
		if status != git.StatusUnknown {
			t.Fatalf("status = %s, want %s", status, git.StatusUnknown)
		}
	})
}

func TestResolveFileStatus_RejectsSymlinkEscapingWorkdir(t *testing.T) {
	outside := t.TempDir()
	targetPath := filepath.Join(outside, "sensitive.txt")
	if err := os.WriteFile(targetPath, []byte("SECRET"), 0o600); err != nil {
		t.Fatalf("failed to create sensitive file: %v", err)
	}

	workDir := t.TempDir()
	linkName := "leak.txt"
	linkPath := filepath.Join(workDir, linkName)
	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Skipf("symlinks unsupported in test env: %v", err)
	}

	client := &mockGitClient{fileExists: map[string]bool{linkName: false}}
	status, err := resolveFileStatus(client, workDir, "HEAD", linkName)
	if err == nil {
		t.Fatalf("expected symlink escape to be rejected; got status %s", status)
	}
	if status != git.StatusUnknown {
		t.Fatalf("status = %s, want Unknown on rejection", status)
	}
}

func TestResolveFileStatus_AllowsInRepoSymlink(t *testing.T) {
	workDir := t.TempDir()
	targetName := "real.txt"
	targetPath := filepath.Join(workDir, targetName)
	if err := os.WriteFile(targetPath, []byte("ok"), 0o644); err != nil {
		t.Fatalf("failed to create real file: %v", err)
	}
	linkName := "alias.txt"
	linkPath := filepath.Join(workDir, linkName)
	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}

	client := &mockGitClient{fileExists: map[string]bool{linkName: false}}
	status, err := resolveFileStatus(client, workDir, "HEAD", linkName)
	if err != nil {
		t.Fatalf("resolveFileStatus returned error: %v", err)
	}
	if status != git.StatusAdded {
		t.Fatalf("status = %s, want %s", status, git.StatusAdded)
	}
}

func TestNormalizeFileList(t *testing.T) {
	input := []string{"", ".", "./cmd/main.go", "cmd/main.go", "internal/../internal/service.go", "cmd/main.go"}
	got := normalizeFileList(input)

	if len(got) != 2 {
		t.Fatalf("expected 2 normalized unique files, got %d: %v", len(got), got)
	}
	if got[0] != "cmd/main.go" {
		t.Fatalf("expected first normalized file to be cmd/main.go, got %q", got[0])
	}
	if got[1] != "internal/service.go" {
		t.Fatalf("expected second normalized file to be internal/service.go, got %q", got[1])
	}
}

func TestFindFileStats(t *testing.T) {
	statsByFile := map[string]git.FileStats{
		"./cmd/main.go":            {Additions: 10, Deletions: 2},
		"internal/service/util.go": {Additions: 3, Deletions: 1},
	}

	stats := findFileStats(statsByFile, "cmd/main.go")
	if stats.Additions != 10 || stats.Deletions != 2 {
		t.Fatalf("expected normalized match stats 10/2, got %d/%d", stats.Additions, stats.Deletions)
	}

	stats = findFileStats(statsByFile, "internal/service/util.go")
	if stats.Additions != 3 || stats.Deletions != 1 {
		t.Fatalf("expected exact match stats 3/1, got %d/%d", stats.Additions, stats.Deletions)
	}

	stats = findFileStats(statsByFile, "missing.go")
	if stats.Additions != 0 || stats.Deletions != 0 {
		t.Fatalf("expected zero stats for missing file, got %d/%d", stats.Additions, stats.Deletions)
	}

	stats = findFileStats(nil, "cmd/main.go")
	if stats.Additions != 0 || stats.Deletions != 0 {
		t.Fatalf("expected zero stats for nil map, got %d/%d", stats.Additions, stats.Deletions)
	}
}
