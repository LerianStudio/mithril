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
	perLinterTimeout := fs.Duration("linter-timeout", lint.DefaultPerLinterTimeout, "Per-linter timeout")
	maxConcurrency := fs.Int("linter-concurrency", lint.DefaultMaxConcurrency, "Max concurrent linters")
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
	changedFiles := s.GetAnalyzableFilesMap()

	allFiles := s.GetAnalyzableFiles()
	packages := s.GetPackages()
	inputs := make([]lint.RunnerInput, 0, len(linters))
	for _, linter := range linters {
		inputs = append(inputs, lint.RunnerInput{
			Linter:  linter,
			Targets: lint.SelectTargets(linter, allFiles, packages),
		})
	}

	runner := lint.NewRunner()
	runner.PerLinterTimeout = *perLinterTimeout
	runner.MaxConcurrency = *maxConcurrency
	aggregateResult := runner.Run(ctx, projectDir, inputs, changedFiles)

	lint.Deduplicate(aggregateResult)
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

