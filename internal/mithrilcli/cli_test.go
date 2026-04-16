package mithrilcli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseInvocation_DefaultsToRunAll(t *testing.T) {
	command, args, ok := parseInvocation(nil)
	if !ok {
		t.Fatal("expected parse to succeed")
	}
	if command != "run-all" {
		t.Fatalf("expected run-all, got %q", command)
	}
	if len(args) != 0 {
		t.Fatalf("expected empty args, got %v", args)
	}
}

func TestParseInvocation_OptionsDefaultToRunAll(t *testing.T) {
	command, args, ok := parseInvocation([]string{"--base=main", "--head=HEAD"})
	if !ok {
		t.Fatal("expected parse to succeed")
	}
	if command != "run-all" {
		t.Fatalf("expected run-all, got %q", command)
	}
	if len(args) != 2 {
		t.Fatalf("expected 2 args, got %d", len(args))
	}
}

func TestParseInvocation_Subcommand(t *testing.T) {
	command, args, ok := parseInvocation([]string{"scope-detector", "--base=main"})
	if !ok {
		t.Fatal("expected parse to succeed")
	}
	if command != "scope-detector" {
		t.Fatalf("expected scope-detector, got %q", command)
	}
	if len(args) != 1 || args[0] != "--base=main" {
		t.Fatalf("unexpected args: %v", args)
	}
}

func TestParseInvocation_UnknownCommand(t *testing.T) {
	command, args, ok := parseInvocation([]string{"totally-unknown"})
	if ok {
		t.Fatal("expected parse to fail")
	}
	if command != "" {
		t.Fatalf("expected empty command, got %q", command)
	}
	if args != nil {
		t.Fatalf("expected nil args, got %v", args)
	}
}

func TestPrintUsage(t *testing.T) {
	var buf bytes.Buffer
	printUsage(&buf)
	output := buf.String()

	expected := []string{
		"Mithril CLI",
		"mithril [flags]",
		"run-all",
		"--unstaged",
		"--staged",
		"--all-modified",
		"--compare --base=main --head=HEAD",
		"scope-detector",
		"static-analysis",
		"ast-extractor",
		"call-graph",
		"data-flow",
		"compile-context",
		"Single binary with in-process subcommand dispatch",
	}

	for _, token := range expected {
		if !strings.Contains(output, token) {
			t.Fatalf("expected usage output to contain %q", token)
		}
	}
}

func TestExecuteCommand_UsesInProcessRunner(t *testing.T) {
	original := commandRunners
	defer func() { commandRunners = original }()

	called := false
	commandRunners = map[string]commandRunner{
		"scope-detector": func(args []string, stdout io.Writer, stderr io.Writer) error {
			called = true
			return nil
		},
	}

	if err := executeCommand("scope-detector", []string{"--base=main"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("expected in-process runner to be called")
	}
}

func TestRun_NoArgsExecutesRunAll(t *testing.T) {
	original := commandRunners
	defer func() { commandRunners = original }()

	called := false
	commandRunners = map[string]commandRunner{
		"run-all": func(args []string, stdout io.Writer, stderr io.Writer) error {
			called = true
			return nil
		},
	}

	if err := Run("dev", nil, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("expected run-all runner to be called")
	}
}

// initTempGitRepo initialises a minimal git repo inside a fresh t.TempDir() so
// real-runner E2E tests can exercise the scope detector without depending on
// the repo the tests run inside. It seeds the repo with a single commit so
// `git diff HEAD` works, then stages a new file so the detector has
// something to report. Skips the test when git is not on PATH.
func initTempGitRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not available; skipping real-runner E2E test")
	}
	dir := t.TempDir()
	runGit := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, string(output))
		}
	}
	// Compatible with all Git versions; branch name is not required here.
	runGit("init", "-q")
	runGit("config", "user.email", "test@example.com")
	runGit("config", "user.name", "Test User")
	runGit("config", "commit.gpgsign", "false")

	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("base\n"), 0o644); err != nil {
		t.Fatalf("write README: %v", err)
	}
	runGit("add", "README.md")
	runGit("commit", "-q", "-m", "initial")

	// Add and stage a new file to produce a non-empty scope.
	if err := os.WriteFile(filepath.Join(dir, "service.go"), []byte("package service\n\nfunc Hello() string { return \"hi\" }\n"), 0o644); err != nil {
		t.Fatalf("write service.go: %v", err)
	}
	runGit("add", "service.go")
	return dir
}

// TestRun_ScopeDetectorEndToEnd_RealRunner exercises the real scope-detector
// runner (no commandRunners stubbing) against a throwaway git repository and
// asserts that a well-formed scope.json is written to disk. This closes the
// coverage gap flagged by C16: the stub-based tests above only verify dispatch
// wiring — this test verifies the full post-dispatch execution path is still
// wired to a working implementation.
func TestRun_ScopeDetectorEndToEnd_RealRunner(t *testing.T) {
	workDir := initTempGitRepo(t)
	scopePath := filepath.Join(workDir, "scope.json")

	var stdout, stderr bytes.Buffer
	args := []string{
		"scope-detector",
		"--workdir=" + workDir,
		"--output=" + scopePath,
		"--staged",
	}
	if err := Run("dev", args, &stdout, &stderr); err != nil {
		t.Fatalf("Run(scope-detector) unexpected error: %v\nstderr: %s", err, stderr.String())
	}

	data, err := os.ReadFile(scopePath) // #nosec G304 — path built from t.TempDir()
	if err != nil {
		t.Fatalf("scope.json was not written: %v", err)
	}
	var parsed struct {
		Language string `json:"language"`
		Files    struct {
			Added    []string `json:"added"`
			Modified []string `json:"modified"`
			Deleted  []string `json:"deleted"`
		} `json:"files"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("scope.json did not parse: %v\nraw: %s", err, string(data))
	}
	// Real runner must have detected our seeded staged .go file and
	// resolved language to "go" (or at least a non-empty value).
	if parsed.Language == "" {
		t.Errorf("expected non-empty language in scope.json, got empty\nscope.json: %s", string(data))
	}
	found := false
	for _, f := range parsed.Files.Added {
		if filepath.Base(f) == "service.go" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected added file 'service.go' in scope.json, got %+v", parsed.Files)
	}
}

func TestRun_ScopeDetectorExecutesRunner(t *testing.T) {
	original := commandRunners
	defer func() { commandRunners = original }()

	called := false
	commandRunners = map[string]commandRunner{
		"scope-detector": func(args []string, stdout io.Writer, stderr io.Writer) error {
			called = true
			if len(args) != 1 || args[0] != "--unstaged" {
				t.Fatalf("unexpected args: %v", args)
			}
			return nil
		},
	}

	if err := Run("dev", []string{"scope-detector", "--unstaged"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("expected scope-detector runner to be called")
	}
}
