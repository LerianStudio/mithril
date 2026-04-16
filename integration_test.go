//go:build integration

// Package main integration tests exercise the shipped `mithril` binary via
// exec.Command. They replace the former cmd/run-all binary-integration tests
// (see cmd/run-all/main_test.go before deletion) and are gated behind the
// `integration` build tag so normal `go test ./...` runs stay fast and
// hermetic. Run with:
//
//	go test -tags=integration ./...
package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var (
	integrationBinaryOnce sync.Once
	integrationBinaryPath string
	integrationBinaryErr  error
	integrationBinaryDir  string
)

func cleanupBinary() {
	if integrationBinaryDir != "" {
		_ = os.RemoveAll(integrationBinaryDir)
	}
}

func TestMain(m *testing.M) {
	code := m.Run()
	cleanupBinary()
	os.Exit(code)
}

// buildMithrilBinary builds `mithril` once per test binary and returns its
// absolute path.
func buildMithrilBinary(t *testing.T) string {
	t.Helper()
	integrationBinaryOnce.Do(func() {
		out, err := os.MkdirTemp("", "mithril-integration-*")
		if err != nil {
			integrationBinaryErr = err
			return
		}
		integrationBinaryDir = out
		bin := filepath.Join(out, "mithril")
		build := exec.Command("go", "build", "-o", bin, ".")
		if output, err := build.CombinedOutput(); err != nil {
			integrationBinaryErr = &buildFailure{Err: err, Output: string(output)}
			return
		}
		integrationBinaryPath = bin
	})
	if integrationBinaryErr != nil {
		t.Fatalf("failed to build mithril binary: %v", integrationBinaryErr)
	}
	return integrationBinaryPath
}

type buildFailure struct {
	Err    error
	Output string
}

func (b *buildFailure) Error() string { return b.Err.Error() + ": " + b.Output }

// TestIntegration_Version ensures `mithril --version` prints the expected
// preamble and does not panic.
func TestIntegration_Version(t *testing.T) {
	bin := buildMithrilBinary(t)
	output, err := exec.Command(bin, "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("--version failed: %v\n%s", err, string(output))
	}
	if !strings.HasPrefix(string(output), "mithril version ") {
		t.Fatalf("unexpected version output: %s", string(output))
	}
}

// TestIntegration_Help ensures `mithril --help` prints the CLI overview
// including subcommand names.
func TestIntegration_Help(t *testing.T) {
	bin := buildMithrilBinary(t)
	output, _ := exec.Command(bin, "--help").CombinedOutput()
	for _, want := range []string{"Mithril CLI", "run-all", "scope-detector", "compile-context"} {
		if !strings.Contains(string(output), want) {
			t.Errorf("help output missing %q\n%s", want, string(output))
		}
	}
}

// TestIntegration_AllPhasesSkipped runs the shipped binary with every phase
// skipped and verifies the skip banners appear in stderr. This replaces
// cmd/run-all/main_test.go#TestRun_AllPhasesSkipped.
func TestIntegration_AllPhasesSkipped(t *testing.T) {
	bin := buildMithrilBinary(t)
	outDir := t.TempDir()
	cmd := exec.Command(bin,
		"--output="+outDir,
		"--skip=scope,static-analysis,ast,callgraph,dataflow,context",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("expected success, got %v\nstderr: %s", err, stderr.String())
	}
	for _, want := range []string{
		"[SKIP] scope", "[SKIP] static-analysis", "[SKIP] ast",
		"[SKIP] callgraph", "[SKIP] dataflow", "[SKIP] context",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr missing %q\nstderr: %s", want, stderr.String())
		}
	}
}

// TestIntegration_InvalidFlagCombinations verifies mutually exclusive flag
// combinations exit non-zero.
func TestIntegration_InvalidFlagCombinations(t *testing.T) {
	bin := buildMithrilBinary(t)
	cases := [][]string{
		{"--files=README.md", "--base=main"},
		{"--unstaged", "--base=main"},
		{"--unstaged", "--staged"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			output, err := exec.Command(bin, args...).CombinedOutput()
			if err == nil {
				t.Fatalf("expected non-zero exit for %v, got output: %s", args, string(output))
			}
		})
	}
}
