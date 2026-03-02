// Package main implements the static-analysis binary.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lerianstudio/mithril/internal/lint"
	"github.com/lerianstudio/mithril/internal/output"
	"github.com/lerianstudio/mithril/internal/scope"
)

func main() {
	// Parse flags
	scopePath := flag.String("scope", "", "Path to scope.json (default: .ring/codereview/scope.json)")
	outputPath := flag.String("output", "", "Output directory (default: .ring/codereview/)")
	verbose := flag.Bool("v", false, "Verbose output")
	timeout := flag.Duration("timeout", 5*time.Minute, "Timeout for analysis")
	flag.Parse()

	// Determine project directory (current working directory)
	projectDir, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed to get working directory: %v", err)
	}

	// Set default paths
	if *scopePath == "" {
		*scopePath = scope.DefaultScopePath(projectDir)
	}
	if *outputPath == "" {
		*outputPath = output.DefaultOutputDir(projectDir)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Read scope
	if *verbose {
		log.Printf("Reading scope from: %s", *scopePath)
	}
	s, err := scope.ReadScopeJSON(*scopePath)
	if err != nil {
		if *verbose {
			log.Printf("scope read detail: %v", err)
		}
		log.Fatalf("Failed to read scope")
	}

	// Get language
	lang := s.GetLanguage()
	if *verbose {
		log.Printf("Detected language: %s", lang)
	}

	// Initialize registry and register linters
	registry := lint.NewRegistry()
	registerLinters(registry)

	// Get available linters based on detected language
	linters := selectAvailableLinters(ctx, registry, lang, s)
	if len(linters) == 0 {
		log.Printf("Warning: No linters available for language: %s", lang)
	}

	if *verbose {
		log.Printf("Available linters: %d", len(linters))
		for _, l := range linters {
			log.Printf("  - %s", l.Name())
		}
	}

	// Run all available linters
	aggregateResult := lint.NewResult()
	changedFiles := s.GetAllFilesMap()

	for _, linter := range linters {
		if *verbose {
			log.Printf("Running %s...", linter.Name())
		}

		// Get files/packages for this linter
		targets := selectTargets(linter, lang, s)

		result, err := linter.Run(ctx, projectDir, targets)
		if err != nil {
			log.Printf("Warning: %s failed: %v", linter.Name(), err)
			aggregateResult.Errors = append(aggregateResult.Errors, fmt.Sprintf("%s: %v", linter.Name(), err))
			continue
		}
		if result == nil {
			log.Printf("Warning: %s returned nil result", linter.Name())
			continue
		}

		// Filter to changed files only and merge
		filtered := result.FilterByFiles(changedFiles)
		aggregateResult.Merge(filtered)

		if *verbose {
			log.Printf("  %s: %d findings", linter.Name(), len(filtered.Findings))
		}
	}

	// Deduplicate findings (same file:line:message from different tools)
	deduplicateFindings(aggregateResult)

	// Ensure output directory exists
	writer := output.NewLintWriter(*outputPath)
	if err := writer.EnsureDir(); err != nil {
		if *verbose {
			log.Printf("output directory detail: %v", err)
		}
		log.Fatalf("Failed to create output directory")
	}

	// Write results
	if err := writer.WriteResult(aggregateResult); err != nil {
		if *verbose {
			log.Printf("write result detail: %v", err)
		}
		log.Fatalf("Failed to write results")
	}

	// Write language-specific result
	if err := writer.WriteLanguageResult(lang, aggregateResult); err != nil {
		if *verbose {
			log.Printf("write language detail: %v", err)
		}
		log.Fatalf("Failed to write language result")
	}

	if lang == lint.LanguageMixed {
		languages := s.Languages
		if len(languages) == 0 {
			languages = []string{"go", "typescript", "python"}
		}
		for _, language := range languages {
			normalized := scope.NormalizeLanguage(language)
			if normalized == "" {
				continue
			}
			perLanguage := filterFindingsByLanguage(aggregateResult, normalized)
			if err := writer.WriteLanguageResult(normalized, perLanguage); err != nil {
				log.Printf("Warning: Failed to write %s language result: %v", normalized, err)
			}
		}
	}

	// Print summary
	fmt.Printf("Static analysis complete:\n")
	fmt.Printf("  Files analyzed: %d\n", len(changedFiles))
	fmt.Printf("  Critical: %d\n", aggregateResult.Summary.Critical)
	fmt.Printf("  High: %d\n", aggregateResult.Summary.High)
	fmt.Printf("  Warning: %d\n", aggregateResult.Summary.Warning)
	fmt.Printf("  Info: %d\n", aggregateResult.Summary.Info)
	fmt.Printf("  Unknown: %d\n", aggregateResult.Summary.Unknown)
	fmt.Printf("  Output: %s\n", filepath.Join(*outputPath, "static-analysis.json"))

	if len(aggregateResult.Errors) > 0 {
		fmt.Printf("\nWarnings during analysis:\n")
		for _, e := range aggregateResult.Errors {
			fmt.Printf("  - %s\n", e)
		}
	}
}

func filterFindingsByLanguage(result *lint.Result, language lint.Language) *lint.Result {
	if result == nil {
		return lint.NewResult()
	}

	filtered := lint.NewResult()
	for name, version := range result.ToolVersions {
		filtered.ToolVersions[name] = version
	}
	filtered.Errors = append(filtered.Errors, result.Errors...)

	for _, finding := range result.Findings {
		if normalizeFindingLanguage(finding.File) == language {
			filtered.AddFinding(finding)
		}
	}

	return filtered
}

func normalizeFindingLanguage(filePath string) lint.Language {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".go":
		return lint.LanguageGo
	case ".ts", ".tsx", ".js", ".jsx":
		return lint.LanguageTypeScript
	case ".py":
		return lint.LanguagePython
	default:
		return lint.Language("")
	}
}

// selectTargets chooses files/packages for a linter based on its preference.
// Falls back to prior language-based defaults when a linter does not specify.
func selectTargets(linter lint.Linter, lang lint.Language, s *scope.ScopeJSON) []string {
	if selector, ok := linter.(lint.TargetSelector); ok {
		switch selector.TargetKind() {
		case lint.TargetKindPackages:
			if pkgs := s.GetPackages(); len(pkgs) > 0 {
				return pkgs
			}
			return nil // let linter use its default
		case lint.TargetKindFiles:
			if files := s.GetAllFiles(); len(files) > 0 {
				return files
			}
			return nil
		case lint.TargetKindProject:
			return nil
		}
	}

	// Legacy behavior by language as a fallback.
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

// selectAvailableLinters chooses available linters based on scope metadata.
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

// registerLinters adds all linters to the registry.
func registerLinters(r *lint.Registry) {
	// Go linters
	r.Register(lint.NewGolangciLint())
	r.Register(lint.NewStaticcheck())
	r.Register(lint.NewGosec())

	// TypeScript linters
	r.Register(lint.NewTSC())
	r.Register(lint.NewESLint())

	// Python linters
	r.Register(lint.NewRuff())
	r.Register(lint.NewMypy())
	r.Register(lint.NewPylint())
	r.Register(lint.NewBandit())
}

// deduplicateFindings removes duplicate findings based on file:line:message.
func deduplicateFindings(result *lint.Result) {
	seen := make(map[string]int)
	unique := make([]lint.Finding, 0)

	// Reset summary
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
			msg := fmt.Sprintf("unknown severity %q for finding %s:%d (%s)", f.Severity, f.File, f.Line, f.Message)
			result.Errors = append(result.Errors, msg)
			log.Printf("Warning: %s", msg)
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
