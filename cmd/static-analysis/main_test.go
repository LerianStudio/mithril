package main

import (
	"context"
	"testing"

	"github.com/lerianstudio/mithril/internal/lint"
	"github.com/lerianstudio/mithril/internal/scope"
)

func TestDeduplicateFindings_KeepHighestSeverity(t *testing.T) {
	result := lint.NewResult()
	result.Findings = []lint.Finding{
		{Tool: "golangci-lint", File: "main.go", Line: 10, Message: "dangerous call", Severity: lint.SeverityWarning},
		{Tool: "gosec", File: "main.go", Line: 10, Message: "dangerous call", Severity: lint.SeverityCritical},
	}

	deduplicateFindings(result)

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding after deduplication, got %d", len(result.Findings))
	}
	if result.Findings[0].Severity != lint.SeverityCritical {
		t.Fatalf("expected critical finding to be kept, got %s", result.Findings[0].Severity)
	}
	if result.Summary.Critical != 1 {
		t.Fatalf("expected critical summary count to be 1, got %d", result.Summary.Critical)
	}
}

func TestSeverityRank(t *testing.T) {
	if severityRank(lint.SeverityCritical) <= severityRank(lint.SeverityHigh) {
		t.Fatal("expected critical severity rank to be higher than high")
	}
	if severityRank(lint.SeverityHigh) <= severityRank(lint.SeverityWarning) {
		t.Fatal("expected high severity rank to be higher than warning")
	}
	if severityRank(lint.SeverityWarning) <= severityRank(lint.SeverityInfo) {
		t.Fatal("expected warning severity rank to be higher than info")
	}
}

func TestFilterFindingsByLanguage(t *testing.T) {
	result := lint.NewResult()
	result.AddFinding(lint.Finding{File: "main.go", Line: 1, Message: "go issue", Severity: lint.SeverityWarning})
	result.AddFinding(lint.Finding{File: "web/app.ts", Line: 2, Message: "ts issue", Severity: lint.SeverityWarning})
	result.AddFinding(lint.Finding{File: "svc/worker.py", Line: 3, Message: "py issue", Severity: lint.SeverityWarning})

	goOnly := filterFindingsByLanguage(result, lint.LanguageGo)
	if len(goOnly.Findings) != 1 {
		t.Fatalf("expected 1 go finding, got %d", len(goOnly.Findings))
	}
	if goOnly.Findings[0].File != "main.go" {
		t.Fatalf("unexpected go finding file %q", goOnly.Findings[0].File)
	}

	tsOnly := filterFindingsByLanguage(result, lint.LanguageTypeScript)
	if len(tsOnly.Findings) != 1 || tsOnly.Findings[0].File != "web/app.ts" {
		t.Fatalf("unexpected typescript filtering result: %+v", tsOnly.Findings)
	}
}

type stubLinter struct {
	name      string
	language  lint.Language
	available bool
	target    lint.TargetKind
}

func (s stubLinter) Name() string { return s.name }

func (s stubLinter) Language() lint.Language { return s.language }

func (s stubLinter) Available(ctx context.Context) bool { return s.available }

func (s stubLinter) Version(ctx context.Context) (string, error) { return "test", nil }

func (s stubLinter) Run(ctx context.Context, projectDir string, files []string) (*lint.Result, error) {
	return lint.NewResult(), nil
}

func (s stubLinter) TargetKind() lint.TargetKind { return s.target }

func TestSelectTargets_UsesTargetSelectorKinds(t *testing.T) {
	s := &scope.ScopeJSON{
		Files: scope.FilesByStatus{
			Modified: []string{"service/main.go"},
			Added:    []string{"web/app.ts"},
		},
		Packages: []string{"github.com/acme/project/service"},
	}

	packages := selectTargets(stubLinter{target: lint.TargetKindPackages}, lint.LanguageGo, s)
	if len(packages) != 1 || packages[0] != "github.com/acme/project/service" {
		t.Fatalf("expected package targets, got %v", packages)
	}

	files := selectTargets(stubLinter{target: lint.TargetKindFiles}, lint.LanguageGo, s)
	if len(files) != 2 {
		t.Fatalf("expected file targets, got %v", files)
	}

	project := selectTargets(stubLinter{target: lint.TargetKindProject}, lint.LanguageGo, s)
	if project != nil {
		t.Fatalf("expected nil targets for project kind, got %v", project)
	}
}

func TestSelectAvailableLinters_MixedLanguageDeduplicatesByName(t *testing.T) {
	registry := lint.NewRegistry()
	registry.Register(stubLinter{name: "shared", language: lint.LanguageGo, available: true})
	registry.Register(stubLinter{name: "shared", language: lint.LanguageTypeScript, available: true})
	registry.Register(stubLinter{name: "ts-only", language: lint.LanguageTypeScript, available: true})
	registry.Register(stubLinter{name: "py-off", language: lint.LanguagePython, available: false})

	s := &scope.ScopeJSON{Languages: []string{"go", "typescript", "python"}}
	linters := selectAvailableLinters(context.Background(), registry, lint.LanguageMixed, s)

	if len(linters) != 2 {
		t.Fatalf("expected 2 available deduplicated linters, got %d", len(linters))
	}

	names := map[string]bool{}
	for _, linter := range linters {
		names[linter.Name()] = true
	}
	if !names["shared"] || !names["ts-only"] {
		t.Fatalf("unexpected linter set: %v", names)
	}
}
