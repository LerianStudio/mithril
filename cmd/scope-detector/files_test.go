package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSplitCSV(t *testing.T) {
	got := splitCSV(" cmd/*.go , ,web/**/*.ts,internal/*.py ")
	want := []string{"cmd/*.go", "web/**/*.ts", "internal/*.py"}

	if len(got) != len(want) {
		t.Fatalf("splitCSV length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitCSV[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestNormalizePatterns(t *testing.T) {
	got := normalizePatterns([]string{"", " cmd/*.go ", "cmd/*.go", "web/*.ts", "web/*.ts"})
	want := []string{"cmd/*.go", "web/*.ts"}

	if len(got) != len(want) {
		t.Fatalf("normalizePatterns length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("normalizePatterns[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestReadPatternsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "patterns.txt")
	content := strings.Join([]string{
		"# comment",
		"cmd/*.go",
		"",
		"web/**/*.ts",
		"   internal/*.py   ",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write patterns file: %v", err)
	}

	patterns, err := readPatternsFile(path)
	if err != nil {
		t.Fatalf("readPatternsFile returned error: %v", err)
	}

	want := []string{"cmd/*.go", "web/**/*.ts", "internal/*.py"}
	if len(patterns) != len(want) {
		t.Fatalf("patterns length = %d, want %d", len(patterns), len(want))
	}
	for i := range want {
		if patterns[i] != want[i] {
			t.Fatalf("patterns[%d] = %q, want %q", i, patterns[i], want[i])
		}
	}
}

func TestResolveFilePatterns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "patterns.txt")
	content := "web/**/*.ts\ncmd/*.go\ncmd/*.go\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write patterns file: %v", err)
	}

	patterns, err := resolveFilePatterns("cmd/*.go,internal/*.py", path)
	if err != nil {
		t.Fatalf("resolveFilePatterns returned error: %v", err)
	}

	want := []string{"cmd/*.go", "internal/*.py", "web/**/*.ts"}
	if len(patterns) != len(want) {
		t.Fatalf("patterns length = %d, want %d", len(patterns), len(want))
	}
	for i := range want {
		if patterns[i] != want[i] {
			t.Fatalf("patterns[%d] = %q, want %q", i, patterns[i], want[i])
		}
	}
}

func TestRun_MutualExclusivity(t *testing.T) {
	original := snapshotMainFlags()
	t.Cleanup(func() { restoreMainFlags(original) })

	*filesFlag = "cmd/*.go"
	*filesFrom = ""
	*baseRef = "main"
	*headRef = "HEAD"
	*unstaged = false
	*outputPath = ""
	*workDir = t.TempDir()
	*showVersion = false
	*verbose = false

	err := run()
	if err == nil || !strings.Contains(err.Error(), "cannot be used") {
		t.Fatalf("expected mutual exclusivity error for files + refs, got %v", err)
	}

	*filesFlag = ""
	*baseRef = "main"
	*headRef = ""
	*unstaged = true

	err = run()
	if err == nil || !strings.Contains(err.Error(), "--unstaged cannot be used") {
		t.Fatalf("expected mutual exclusivity error for unstaged + refs, got %v", err)
	}
}

type mainFlagSnapshot struct {
	baseRef     string
	headRef     string
	filesFlag   string
	filesFrom   string
	unstaged    bool
	outputPath  string
	workDir     string
	showVersion bool
	verbose     bool
}

func snapshotMainFlags() mainFlagSnapshot {
	return mainFlagSnapshot{
		baseRef:     *baseRef,
		headRef:     *headRef,
		filesFlag:   *filesFlag,
		filesFrom:   *filesFrom,
		unstaged:    *unstaged,
		outputPath:  *outputPath,
		workDir:     *workDir,
		showVersion: *showVersion,
		verbose:     *verbose,
	}
}

func restoreMainFlags(s mainFlagSnapshot) {
	*baseRef = s.baseRef
	*headRef = s.headRef
	*filesFlag = s.filesFlag
	*filesFrom = s.filesFrom
	*unstaged = s.unstaged
	*outputPath = s.outputPath
	*workDir = s.workDir
	*showVersion = s.showVersion
	*verbose = s.verbose
}
