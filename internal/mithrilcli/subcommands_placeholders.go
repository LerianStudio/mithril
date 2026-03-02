package mithrilcli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/lerianstudio/mithril/internal/lint"
	"github.com/lerianstudio/mithril/internal/output"
	"github.com/lerianstudio/mithril/internal/scope"
)

func runStaticAnalysis(args []string, stdout io.Writer, stderr io.Writer) error {
	fs := flag.NewFlagSet("static-analysis", flag.ContinueOnError)
	fs.SetOutput(stderr)
	scopePath := fs.String("scope", "", "Path to scope.json (default: .ring/codereview/scope.json)")
	outputPath := fs.String("output", "", "Output directory (default: .ring/codereview/)")
	verbose := fs.Bool("v", false, "Verbose output")
	fs.BoolVar(verbose, "verbose", false, "Verbose output")
	timeout := fs.Duration("timeout", 5*time.Minute, "Timeout for analysis")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	projectDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}
	if *scopePath == "" {
		*scopePath = scope.DefaultScopePath(projectDir)
	}
	if *outputPath == "" {
		*outputPath = output.DefaultOutputDir(projectDir)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if *verbose {
		_, _ = fmt.Fprintf(stderr, "Reading scope from: %s\n", *scopePath)
	}
	s, err := scope.ReadScopeJSON(*scopePath)
	if err != nil {
		return fmt.Errorf("failed to read scope: %w", err)
	}

	lang := s.GetLanguage()
	registry := lint.NewRegistry()
	registerLinters(registry)
	linters := selectAvailableLinters(ctx, registry, lang, s)
	aggregateResult := lint.NewResult()
	changedFiles := s.GetAllFilesMap()

	for _, linter := range linters {
		targets := selectTargets(linter, lang, s)
		result, runErr := linter.Run(ctx, projectDir, targets)
		if runErr != nil {
			aggregateResult.Errors = append(aggregateResult.Errors, fmt.Sprintf("%s: %v", linter.Name(), runErr))
			continue
		}
		if result == nil {
			continue
		}
		aggregateResult.Merge(result.FilterByFiles(changedFiles))
	}

	deduplicateFindings(aggregateResult)
	writer := output.NewLintWriter(*outputPath)
	if err := writer.EnsureDir(); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	if err := writer.WriteResult(aggregateResult); err != nil {
		return fmt.Errorf("failed to write results: %w", err)
	}
	if err := writer.WriteLanguageResult(lang, aggregateResult); err != nil {
		return fmt.Errorf("failed to write language result: %w", err)
	}

	_, _ = fmt.Fprintf(stdout, "Static analysis complete:\n")
	_, _ = fmt.Fprintf(stdout, "  Files analyzed: %d\n", len(changedFiles))
	_, _ = fmt.Fprintf(stdout, "  Critical: %d\n", aggregateResult.Summary.Critical)
	_, _ = fmt.Fprintf(stdout, "  High: %d\n", aggregateResult.Summary.High)
	_, _ = fmt.Fprintf(stdout, "  Warning: %d\n", aggregateResult.Summary.Warning)
	_, _ = fmt.Fprintf(stdout, "  Info: %d\n", aggregateResult.Summary.Info)
	_, _ = fmt.Fprintf(stdout, "  Unknown: %d\n", aggregateResult.Summary.Unknown)
	_, _ = fmt.Fprintf(stdout, "  Output: %s\n", filepath.Join(*outputPath, "static-analysis.json"))

	if len(aggregateResult.Errors) > 0 {
		_, _ = fmt.Fprintf(stdout, "\nWarnings during analysis:\n")
		for _, e := range aggregateResult.Errors {
			_, _ = fmt.Fprintf(stdout, "  - %s\n", e)
		}
	}

	return nil
}

func registerLinters(r *lint.Registry) {
	r.Register(lint.NewGolangciLint())
	r.Register(lint.NewStaticcheck())
	r.Register(lint.NewGosec())
	r.Register(lint.NewTSC())
	r.Register(lint.NewESLint())
	r.Register(lint.NewRuff())
	r.Register(lint.NewMypy())
	r.Register(lint.NewPylint())
	r.Register(lint.NewBandit())
}

func selectTargets(linter lint.Linter, lang lint.Language, s *scope.ScopeJSON) []string {
	if selector, ok := linter.(lint.TargetSelector); ok {
		switch selector.TargetKind() {
		case lint.TargetKindPackages:
			if pkgs := s.GetPackages(); len(pkgs) > 0 {
				return pkgs
			}
			return nil
		case lint.TargetKindFiles:
			if files := s.GetAllFiles(); len(files) > 0 {
				return files
			}
			return nil
		case lint.TargetKindProject:
			return nil
		}
	}
	if lang == lint.LanguageGo {
		if pkgs := s.GetPackages(); len(pkgs) > 0 {
			return pkgs
		}
		return nil
	}
	if files := s.GetAllFiles(); len(files) > 0 {
		return files
	}
	return nil
}

func selectAvailableLinters(ctx context.Context, registry *lint.Registry, lang lint.Language, s *scope.ScopeJSON) []lint.Linter {
	if lang != lint.LanguageMixed {
		return registry.GetAvailableLinters(ctx, lang)
	}
	languageSet := s.Languages
	if len(languageSet) == 0 {
		return registry.GetAvailableLinters(ctx, lang)
	}
	var linters []lint.Linter
	seen := make(map[string]bool)
	for _, language := range languageSet {
		normalized := scope.NormalizeLanguage(language)
		if normalized == "" {
			continue
		}
		for _, linter := range registry.GetAvailableLinters(ctx, normalized) {
			name := linter.Name()
			if !seen[name] {
				linters = append(linters, linter)
				seen[name] = true
			}
		}
	}
	return linters
}

func deduplicateFindings(result *lint.Result) {
	seen := make(map[string]int)
	unique := make([]lint.Finding, 0)
	result.Summary = lint.Summary{}

	for _, f := range result.Findings {
		key := fmt.Sprintf("%s:%d:%s", f.File, f.Line, f.Message)
		idx, exists := seen[key]
		if !exists {
			seen[key] = len(unique)
			unique = append(unique, f)
			continue
		}
		if severityRank(f.Severity) > severityRank(unique[idx].Severity) {
			unique[idx] = f
		}
	}

	for _, f := range unique {
		switch f.Severity {
		case lint.SeverityCritical:
			result.Summary.Critical++
		case lint.SeverityHigh:
			result.Summary.High++
		case lint.SeverityWarning:
			result.Summary.Warning++
		case lint.SeverityInfo:
			result.Summary.Info++
		default:
			result.Summary.Unknown++
			result.Errors = append(result.Errors, fmt.Sprintf("unknown severity %q for finding %s:%d (%s)", f.Severity, f.File, f.Line, f.Message))
		}
	}
	result.Findings = unique
}

func severityRank(severity lint.Severity) int {
	switch severity {
	case lint.SeverityCritical:
		return 4
	case lint.SeverityHigh:
		return 3
	case lint.SeverityWarning:
		return 2
	case lint.SeverityInfo:
		return 1
	default:
		return 0
	}
}
