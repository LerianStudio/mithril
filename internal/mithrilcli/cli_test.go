package mithrilcli

import (
	"bytes"
	"io"
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
