package lint

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DefaultPerLinterTimeout bounds an individual linter's execution.
const DefaultPerLinterTimeout = 90 * time.Second

// DefaultMaxConcurrency caps how many linters run simultaneously.
const DefaultMaxConcurrency = 4

// Runner orchestrates execution of multiple linters against a set of targets.
type Runner struct {
	PerLinterTimeout time.Duration
	MaxConcurrency   int
}

// NewRunner returns a Runner with default settings.
func NewRunner() *Runner {
	return &Runner{
		PerLinterTimeout: DefaultPerLinterTimeout,
		MaxConcurrency:   DefaultMaxConcurrency,
	}
}

// RunnerInput pairs a linter with the targets it should analyze.
type RunnerInput struct {
	Linter  Linter
	Targets []string
}

// Run executes each linter in parallel with a per-linter timeout, merging
// findings into a single Result. Findings are filtered by keepFiles when it
// is non-nil and non-empty.
func (r *Runner) Run(ctx context.Context, projectDir string, inputs []RunnerInput, keepFiles map[string]bool) *Result {
	aggregate := NewResult()
	if len(inputs) == 0 {
		return aggregate
	}

	perTimeout := r.PerLinterTimeout
	if perTimeout <= 0 {
		perTimeout = DefaultPerLinterTimeout
	}
	maxConc := r.MaxConcurrency
	if maxConc <= 0 {
		maxConc = DefaultMaxConcurrency
	}

	type outcome struct {
		linter Linter
		result *Result
		err    error
	}
	outcomes := make([]outcome, len(inputs))

	sem := make(chan struct{}, maxConc)
	var wg sync.WaitGroup
	for i, in := range inputs {
		wg.Add(1)
		go func(idx int, input RunnerInput) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			lctx, cancel := context.WithTimeout(ctx, perTimeout)
			defer cancel()

			res, err := input.Linter.Run(lctx, projectDir, input.Targets)
			outcomes[idx] = outcome{linter: input.Linter, result: res, err: err}
		}(i, in)
	}
	wg.Wait()

	for _, o := range outcomes {
		if o.err != nil {
			aggregate.Errors = append(aggregate.Errors, fmt.Sprintf("%s: %v", o.linter.Name(), o.err))
			continue
		}
		if o.result == nil {
			continue
		}
		merged := o.result
		if len(keepFiles) > 0 {
			merged = o.result.FilterByFiles(keepFiles)
		}
		aggregate.Merge(merged)
	}
	return aggregate
}

// Deduplicate collapses findings sharing (file, line, message), preferring
// the one with higher severity rank, and rebuilds the summary.
func Deduplicate(result *Result) {
	if result == nil {
		return
	}
	seen := make(map[string]int)
	unique := make([]Finding, 0, len(result.Findings))
	result.Summary = Summary{}

	for _, f := range result.Findings {
		key := fmt.Sprintf("%s:%d:%s", f.File, f.Line, f.Message)
		idx, exists := seen[key]
		if !exists {
			seen[key] = len(unique)
			unique = append(unique, f)
			continue
		}
		if SeverityRank(f.Severity) > SeverityRank(unique[idx].Severity) {
			unique[idx] = f
		}
	}

	for _, f := range unique {
		if !result.Summary.IncrementSummary(f.Severity) {
			result.Errors = append(result.Errors, fmt.Sprintf("unknown severity %q for finding %s:%d (%s)", f.Severity, f.File, f.Line, f.Message))
		}
	}
	result.Findings = unique
}

// FileExtensions associated with each linter Language. Used to route files.
var languageExtensions = map[Language]map[string]struct{}{
	LanguageGo:         {".go": {}},
	LanguagePython:     {".py": {}, ".pyi": {}},
	LanguageTypeScript: {".ts": {}, ".tsx": {}, ".js": {}, ".jsx": {}, ".mjs": {}, ".cjs": {}},
}

// filterFilesByLanguage returns only files whose extensions match the language.
// For LanguageMixed or unknown languages, returns files unchanged.
func filterFilesByLanguage(files []string, lang Language) []string {
	exts, ok := languageExtensions[lang]
	if !ok {
		return files
	}
	out := make([]string, 0, len(files))
	for _, f := range files {
		ext := strings.ToLower(filepath.Ext(f))
		if _, match := exts[ext]; match {
			out = append(out, f)
		}
	}
	return out
}

// SelectTargets chooses the target list for a linter based on the linter's
// language and preferred TargetKind, routing files by extension.
//
//	Go linters receive package import paths when available.
//	Other linters receive only files whose extensions match their language.
func SelectTargets(linter Linter, allFiles []string, packages []string) []string {
	lang := linter.Language()
	kind := TargetKindFiles
	if sel, ok := linter.(TargetSelector); ok {
		kind = sel.TargetKind()
	}

	switch kind {
	case TargetKindPackages:
		if len(packages) > 0 {
			return packages
		}
		return nil
	case TargetKindProject:
		return nil
	case TargetKindFiles:
		fallthrough
	default:
		return filterFilesByLanguage(allFiles, lang)
	}
}
