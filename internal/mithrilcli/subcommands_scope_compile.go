package mithrilcli

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/lerianstudio/mithril/internal/context"
	"github.com/lerianstudio/mithril/internal/fileutil"
	"github.com/lerianstudio/mithril/internal/output"
	"github.com/lerianstudio/mithril/internal/scope"
)

func runCompileContext(args []string, stdout io.Writer, stderr io.Writer) error {
	fs := flag.NewFlagSet("compile-context", flag.ContinueOnError)
	fs.SetOutput(stderr)

	inputDir := fs.String("input", ".ring/codereview", "Input directory containing phase outputs")
	outputDir := fs.String("output", "", "Output directory for context files (default: same as input)")
	verbose := fs.Bool("verbose", false, "Enable verbose output")
	fs.BoolVar(verbose, "v", false, "Enable verbose output (shorthand)")

	fs.Usage = func() {
		_, _ = fmt.Fprintf(stderr, "Usage: compile-context [options]\n\n")
		_, _ = fmt.Fprintf(stderr, "Context Compiler - Phase 5 of the codereview system\n\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	if _, err := os.Stat(*inputDir); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("input directory does not exist: %s", *inputDir)
		}
		return fmt.Errorf("cannot access input directory %s: %w", *inputDir, err)
	}

	outDir := *outputDir
	if outDir == "" {
		outDir = *inputDir
	}

	if *verbose {
		_, _ = fmt.Fprintf(stderr, "Input directory: %s\n", *inputDir)
		_, _ = fmt.Fprintf(stderr, "Output directory: %s\n", outDir)
	}

	compiler, err := context.NewCompilerWithValidation(*inputDir, outDir)
	if err != nil {
		return fmt.Errorf("compiler initialization failed: %w", err)
	}
	if err := compiler.Compile(); err != nil {
		return fmt.Errorf("compilation failed: %w", err)
	}

	_, _ = fmt.Fprintln(stdout, "Context compilation complete.")
	return nil
}

func runScopeDetector(args []string, stdout io.Writer, stderr io.Writer) error {
	fs := flag.NewFlagSet("scope-detector", flag.ContinueOnError)
	fs.SetOutput(stderr)

	baseRef := fs.String("base", "", "Base reference (commit/branch). When both refs empty, detects all uncommitted changes")
	headRef := fs.String("head", "", "Head reference (commit/branch). When both refs empty, detects all uncommitted changes")
	filesFlag := fs.String("files", "", "Comma-separated file patterns to analyze (mutually exclusive with --base/--head)")
	filesFrom := fs.String("files-from", "", "Path to file containing file patterns (one per line)")
	staged := fs.Bool("staged", false, "Analyze only staged files")
	unstaged := fs.Bool("unstaged", false, "Analyze only unstaged and untracked files")
	allModified := fs.Bool("all-modified", false, "Analyze all modified files (staged + unstaged)")
	outputPath := fs.String("output", "", "Output file path. Empty = write to stdout")
	workDir := fs.String("workdir", "", "Working directory. Empty = current directory")
	verbose := fs.Bool("v", false, "Enable verbose output")
	fs.BoolVar(verbose, "verbose", false, "Enable verbose output")

	fs.Usage = func() {
		_, _ = fmt.Fprintf(stderr, "Usage: scope-detector [options]\n\n")
		_, _ = fmt.Fprintf(stderr, "Analyzes git diff to detect changed files and project language.\n\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	wd := *workDir
	if wd == "" {
		var err error
		wd, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current directory: %w", err)
		}
	}

	detector := scope.NewDetector(wd)
	detector.SetLogger(func(format string, args ...any) {
		_, _ = fmt.Fprintf(stderr, format+"\n", args...)
	})
	patterns, patternsErr := resolveFilePatterns(*filesFlag, *filesFrom)
	if patternsErr != nil {
		return patternsErr
	}

	var (
		result *scope.ScopeResult
		err    error
	)

	modeCount := 0
	if *staged {
		modeCount++
	}
	if *unstaged {
		modeCount++
	}
	if *allModified {
		modeCount++
	}
	if modeCount > 1 {
		return fmt.Errorf("--staged, --unstaged, and --all-modified are mutually exclusive")
	}

	if len(patterns) > 0 {
		if *baseRef != "" || *headRef != "" || *staged || *unstaged || *allModified {
			return fmt.Errorf("--files/--files-from cannot be used with --base/--head, --staged, --unstaged, or --all-modified")
		}
		expanded, expandErr := scope.ExpandFilePatterns(wd, patterns)
		if expandErr != nil {
			return expandErr
		}
		if len(expanded) == 0 {
			_, _ = fmt.Fprintln(stderr, "Warning: no files matched the provided patterns")
			result = &scope.ScopeResult{Language: scope.LanguageUnknown.String()}
		} else {
			result, err = detector.DetectFromFiles("", expanded)
		}
	} else if *staged {
		if *baseRef != "" || *headRef != "" {
			return fmt.Errorf("--staged cannot be used with --base/--head")
		}
		result, err = detector.DetectStagedChanges()
	} else if *unstaged {
		if *baseRef != "" || *headRef != "" {
			return fmt.Errorf("--unstaged cannot be used with --base/--head")
		}
		result, err = detector.DetectUnstagedChanges()
	} else if *allModified {
		if *baseRef != "" || *headRef != "" {
			return fmt.Errorf("--all-modified cannot be used with --base/--head")
		}
		result, err = detector.DetectAllChanges()
	} else if *baseRef == "" && *headRef == "" {
		result, err = detector.DetectAllChanges()
	} else {
		result, err = detector.DetectFromRefs(*baseRef, *headRef)
	}

	if err != nil {
		return fmt.Errorf("failed to detect scope: %w", err)
	}

	if *verbose {
		_, _ = fmt.Fprintf(stderr, "=== Scope Detector (Verbose) ===\n")
		_, _ = fmt.Fprintf(stderr, "Working directory: %s\n", wd)
		_, _ = fmt.Fprintf(stderr, "Files found: %d\n", result.TotalFiles)
		_, _ = fmt.Fprintf(stderr, "Language detected: %s\n", result.Language)
		_, _ = fmt.Fprintf(stderr, "================================\n")
	}

	scopeOutput := output.NewScopeOutput(result)
	if scopeOutput == nil {
		return fmt.Errorf("failed to create scope output: nil result")
	}

	if *outputPath != "" {
		validatedOutput, err := fileutil.ValidatePath(*outputPath, wd)
		if err != nil {
			return fmt.Errorf("invalid output path: %w", err)
		}
		if err := scopeOutput.WriteToFile(validatedOutput); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		_, _ = fmt.Fprintf(stderr, "Scope written to %s\n", validatedOutput)
		return nil
	}

	if err := scopeOutput.WriteToStdout(); err != nil {
		return fmt.Errorf("failed to write to stdout: %w", err)
	}
	return nil
}

func resolveFilePatterns(filesFlag, filesFrom string) ([]string, error) {
	patterns := splitCSV(filesFlag)
	if filesFrom != "" {
		filePatterns, err := readPatternsFile(filesFrom)
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, filePatterns...)
	}
	return normalizePatterns(patterns), nil
}

func splitCSV(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func readPatternsFile(path string) ([]string, error) {
	cleaned, err := fileutil.ValidatePath(path, ".")
	if err != nil {
		return nil, fmt.Errorf("patterns file path invalid: %w", err)
	}

	file, err := os.Open(cleaned) // #nosec G304 -- ValidatePath rejects traversal and constrains path to workspace root
	if err != nil {
		return nil, fmt.Errorf("failed to read patterns file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	scanner := bufio.NewScanner(file)
	var patterns []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read patterns file: %w", err)
	}
	return patterns, nil
}

func normalizePatterns(patterns []string) []string {
	result := make([]string, 0, len(patterns))
	seen := make(map[string]bool)
	for _, pattern := range patterns {
		trimmed := strings.TrimSpace(pattern)
		if trimmed == "" {
			continue
		}
		if !seen[trimmed] {
			seen[trimmed] = true
			result = append(result, trimmed)
		}
	}
	return result
}
