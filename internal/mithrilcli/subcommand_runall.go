package mithrilcli

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/lerianstudio/mithril/internal/callgraph"
	"github.com/lerianstudio/mithril/internal/fileutil"
	"github.com/lerianstudio/mithril/internal/git"
	"github.com/lerianstudio/mithril/internal/scope"
)

type runAllConfig struct {
	baseRef   string
	headRef   string
	files     string
	filesFrom string
	compare   bool
	staged    bool
	unstaged  bool
	allMod    bool
	outputDir string
	skip      string
	verbose   bool
}

type runAllPhase struct {
	name string
	run  func(cfg *runAllConfig, stdout io.Writer, stderr io.Writer) error
	skip func(cfg *runAllConfig) (bool, string)
}

type scopeJSON = scope.ScopeJSON

type filePair struct {
	BeforePath string `json:"before_path"`
	AfterPath  string `json:"after_path"`
}

func runAll(args []string, stdout io.Writer, stderr io.Writer) error {
	fs := flag.NewFlagSet("run-all", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cfg := &runAllConfig{}
	fs.StringVar(&cfg.baseRef, "base", "main", "Base git reference (commit/branch)")
	fs.StringVar(&cfg.headRef, "head", "HEAD", "Head git reference (commit/branch)")
	fs.BoolVar(&cfg.compare, "compare", false, "Compare refs using --base/--head")
	fs.BoolVar(&cfg.staged, "staged", false, "Analyze only staged files")
	fs.StringVar(&cfg.files, "files", "", "Comma-separated file patterns to analyze")
	fs.StringVar(&cfg.filesFrom, "files-from", "", "Path to file containing file patterns")
	fs.BoolVar(&cfg.unstaged, "unstaged", false, "Analyze only unstaged and untracked files")
	fs.BoolVar(&cfg.allMod, "all-modified", false, "Analyze all modified files (staged + unstaged)")
	fs.StringVar(&cfg.outputDir, "output", ".ring/codereview", "Output directory for all phase results")
	fs.StringVar(&cfg.skip, "skip", "", "Comma-separated list of phases to skip")
	fs.BoolVar(&cfg.verbose, "verbose", false, "Enable verbose output")
	fs.BoolVar(&cfg.verbose, "v", false, "Enable verbose output")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	if err := validateRunAllFlags(fs, cfg, stderr); err != nil {
		return err
	}

	validatedOutputDir, err := fileutil.ValidatePath(cfg.outputDir, ".")
	if err != nil {
		return fmt.Errorf("invalid output directory: %w", err)
	}
	cfg.outputDir = validatedOutputDir
	if err := os.MkdirAll(cfg.outputDir, 0o700); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	if cfg.verbose {
		_, _ = fmt.Fprintf(stderr, "Configuration:\n")
		_, _ = fmt.Fprintf(stderr, "  Base ref: %s\n", cfg.baseRef)
		_, _ = fmt.Fprintf(stderr, "  Head ref: %s\n", cfg.headRef)
		_, _ = fmt.Fprintf(stderr, "  Output directory: %s\n", cfg.outputDir)
		_, _ = fmt.Fprintf(stderr, "\n")
	}

	skipSet := parseSkipList(cfg.skip)
	phases := []runAllPhase{
		{name: "scope", run: runScopePhase},
		{name: "static-analysis", run: runStaticAnalysisPhase, skip: shouldSkipForNoFilesOrMissingScope},
		{name: "ast", run: runASTPhase, skip: shouldSkipForNoFiles},
		{name: "callgraph", run: runCallGraphPhase, skip: shouldSkipForNoFilesOrUnknownLanguage},
		{name: "dataflow", run: runDataFlowPhase, skip: shouldSkipForMissingScope},
		{name: "context", run: runContextPhase},
	}

	failed := false
	for _, phase := range phases {
		if skipSet[phase.name] {
			_, _ = fmt.Fprintf(stderr, "[SKIP] %s: skipped via --skip flag\n", phase.name)
			continue
		}
		if phase.skip != nil {
			if skip, reason := phase.skip(cfg); skip {
				_, _ = fmt.Fprintf(stderr, "[SKIP] %s: %s\n", phase.name, reason)
				continue
			}
		}
		if err := phase.run(cfg, stdout, stderr); err != nil {
			failed = true
			_, _ = fmt.Fprintf(stderr, "[FAIL] %s: %v\n", phase.name, err)
			continue
		}
		_, _ = fmt.Fprintf(stderr, "[PASS] %s\n", phase.name)
	}

	if failed {
		return fmt.Errorf("one or more phases failed")
	}
	return nil
}

func validateRunAllFlags(fs *flag.FlagSet, cfg *runAllConfig, stderr io.Writer) error {
	filesSelected := cfg.files != "" || cfg.filesFrom != ""
	baseSet := false
	headSet := false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "base":
			baseSet = true
		case "head":
			headSet = true
		}
	})
	if baseSet || headSet {
		cfg.compare = true
	}

	modeCount := 0
	if cfg.compare {
		modeCount++
	}
	if cfg.staged {
		modeCount++
	}
	if cfg.unstaged {
		modeCount++
	}
	if cfg.allMod {
		modeCount++
	}
	if filesSelected {
		modeCount++
	}

	if modeCount > 1 {
		_, _ = fmt.Fprintln(stderr, "Error: choose only one mode: --compare, --staged, --unstaged, --all-modified, or --files/--files-from")
		return fmt.Errorf("invalid flag combination")
	}
	if modeCount == 0 {
		cfg.compare = true
	}
	if cfg.compare && !baseSet {
		cfg.baseRef = "main"
	}
	if cfg.compare && !headSet {
		cfg.headRef = "HEAD"
	}
	if !cfg.compare {
		cfg.baseRef = ""
		cfg.headRef = ""
	}

	if filesSelected && (baseSet || headSet) {
		_, _ = fmt.Fprintln(stderr, "Error: --files/--files-from cannot be used with --base/--head")
		return fmt.Errorf("invalid flag combination")
	}
	return nil
}

func runScopePhase(cfg *runAllConfig, _ io.Writer, stderr io.Writer) error {
	args := []string{"--output", filepath.Join(cfg.outputDir, "scope.json")}
	if cfg.unstaged {
		args = append(args, "--unstaged")
	} else if cfg.staged {
		args = append(args, "--staged")
	} else if cfg.allMod {
		args = append(args, "--all-modified")
	} else if cfg.files != "" || cfg.filesFrom != "" {
		if cfg.files != "" {
			args = append(args, "--files", cfg.files)
		}
		if cfg.filesFrom != "" {
			args = append(args, "--files-from", cfg.filesFrom)
		}
	} else {
		args = append(args, "--base", cfg.baseRef, "--head", cfg.headRef)
	}
	if cfg.verbose {
		args = append(args, "-v")
	}
	return runScopeDetector(args, io.Discard, stderr)
}

func runStaticAnalysisPhase(cfg *runAllConfig, stdout io.Writer, stderr io.Writer) error {
	args := []string{"--scope", filepath.Join(cfg.outputDir, "scope.json"), "--output", cfg.outputDir}
	if cfg.verbose {
		args = append(args, "-v")
	}
	return runStaticAnalysis(args, stdout, stderr)
}

func runASTPhase(cfg *runAllConfig, stdout io.Writer, stderr io.Writer) error {
	batchPath, tempDir, err := generateASTBatchFile(cfg)
	if err != nil {
		return err
	}
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()
	args := []string{"--batch", batchPath, "--output", "json"}
	if cfg.verbose {
		args = append(args, "-v")
	}
	var buf bytes.Buffer
	if err := runAstExtractor(args, &buf, stderr); err != nil {
		return err
	}
	scopeData, err := readScopeJSON(cfg.outputDir)
	if err != nil {
		return fmt.Errorf("failed to read scope.json for AST output: %w", err)
	}
	written, err := writeASTOutputsByLanguage(cfg.outputDir, buf.Bytes(), scopeData.Language)
	if err != nil {
		return fmt.Errorf("failed to write AST outputs: %w", err)
	}
	for _, path := range written {
		_, _ = fmt.Fprintf(stdout, "AST output written to: %s\n", path)
	}
	return nil
}

func runCallGraphPhase(cfg *runAllConfig, stdout io.Writer, stderr io.Writer) error {
	astFile, err := detectASTOutputFile(cfg.outputDir)
	if err != nil {
		return err
	}
	args := []string{"--ast", astFile, "--output", cfg.outputDir}
	callgraphLangs, err := languagesForCallgraph(cfg.outputDir)
	if err == nil && len(callgraphLangs) == 1 {
		args = append(args, "--lang", callgraphLangs[0])
	}
	if err == nil && len(callgraphLangs) > 1 {
		if writeErr := writeCallgraphLanguageFile(cfg.outputDir, callgraphLangs); writeErr == nil {
			args = append(args, "--languages-file", callgraphLanguagesFile(cfg.outputDir))
		}
	}
	if cfg.verbose {
		args = append(args, "-v")
	}
	return runCallGraph(args, stdout, stderr)
}

func runDataFlowPhase(cfg *runAllConfig, stdout io.Writer, stderr io.Writer) error {
	args := []string{"--scope", filepath.Join(cfg.outputDir, "scope.json"), "--output", cfg.outputDir}
	if cfg.verbose {
		args = append(args, "-v")
	}
	return runDataFlow(args, stdout, stderr)
}

func runContextPhase(cfg *runAllConfig, stdout io.Writer, stderr io.Writer) error {
	args := []string{"--input", cfg.outputDir, "--output", cfg.outputDir}
	if cfg.verbose {
		args = append(args, "-v")
	}
	return runCompileContext(args, stdout, stderr)
}

func parseSkipList(skip string) map[string]bool {
	skipSet := make(map[string]bool)
	if skip == "" {
		return skipSet
	}
	for _, name := range strings.Split(skip, ",") {
		name = strings.TrimSpace(name)
		if name != "" {
			skipSet[name] = true
		}
	}
	return skipSet
}

func readScopeJSON(outputDir string) (*scopeJSON, error) {
	return scope.ReadScopeJSON(filepath.Join(outputDir, "scope.json"))
}

func shouldSkipForNoFiles(cfg *runAllConfig) (bool, string) {
	scopeData, err := readScopeJSON(cfg.outputDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true, "scope.json missing - skipping dependent phase"
		}
		return false, ""
	}
	totalFiles := len(scopeData.Files.Modified) + len(scopeData.Files.Added) + len(scopeData.Files.Deleted)
	if totalFiles == 0 {
		return true, "No changed files detected"
	}
	return false, ""
}

func shouldSkipForMissingScope(cfg *runAllConfig) (bool, string) {
	_, err := readScopeJSON(cfg.outputDir)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return true, "scope.json missing - skipping dependent phase"
	}
	return false, ""
}

func shouldSkipForNoFilesOrUnknownLanguage(cfg *runAllConfig) (bool, string) {
	if skip, reason := shouldSkipForNoFiles(cfg); skip {
		return skip, reason
	}
	scopeData, err := readScopeJSON(cfg.outputDir)
	if err != nil {
		return false, ""
	}
	language := strings.ToLower(strings.TrimSpace(scopeData.Language))
	if language == "" || language == "unknown" {
		return true, "Unknown language detected"
	}
	return false, ""
}

func shouldSkipForNoFilesOrMissingScope(cfg *runAllConfig) (bool, string) {
	if skip, reason := shouldSkipForMissingScope(cfg); skip {
		return skip, reason
	}
	return shouldSkipForNoFiles(cfg)
}

func generateASTBatchFile(cfg *runAllConfig) (string, string, error) {
	scopeData, err := readScopeJSON(cfg.outputDir)
	if err != nil {
		return "", "", fmt.Errorf("failed to read scope.json: %w", err)
	}
	beforeRef := strings.TrimSpace(scopeData.BaseRef)
	if beforeRef == "" {
		beforeRef = cfg.baseRef
	}
	tempDir, err := os.MkdirTemp("", "mithril-ast-before-*")
	if err != nil {
		return "", "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	var pairs []filePair
	for _, file := range scopeData.Files.Modified {
		beforePath, extractErr := extractFileFromGit(beforeRef, file, tempDir)
		if extractErr != nil {
			return "", "", fmt.Errorf("failed to extract %s from %s: %w", file, beforeRef, extractErr)
		}
		pairs = append(pairs, filePair{BeforePath: beforePath, AfterPath: file})
	}
	for _, file := range scopeData.Files.Added {
		pairs = append(pairs, filePair{AfterPath: file})
	}
	for _, file := range scopeData.Files.Deleted {
		beforePath, extractErr := extractFileFromGit(beforeRef, file, tempDir)
		if extractErr != nil {
			continue
		}
		pairs = append(pairs, filePair{BeforePath: beforePath})
	}

	batchPath := filepath.Join(cfg.outputDir, "ast-batch.json")
	data, err := json.MarshalIndent(pairs, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal batch file: %w", err)
	}
	if err := os.WriteFile(batchPath, data, 0o600); err != nil {
		return "", "", fmt.Errorf("failed to write batch file: %w", err)
	}
	return batchPath, tempDir, nil
}

func extractFileFromGit(ref, filePath, tempDir string) (string, error) {
	if filePath == "" {
		return "", fmt.Errorf("invalid file path: empty")
	}
	if filepath.IsAbs(filePath) {
		return "", fmt.Errorf("invalid file path: absolute paths are not allowed")
	}
	cleaned := filepath.Clean(filePath)
	if strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) || cleaned == ".." {
		return "", fmt.Errorf("invalid file path: contains path traversal")
	}
	destPath := filepath.Join(tempDir, cleaned)
	if err := os.MkdirAll(filepath.Dir(destPath), 0o700); err != nil {
		return "", fmt.Errorf("failed to create temp subdirectory: %w", err)
	}
	client := git.NewClient("")
	content, err := client.ShowFile(ref, filePath)
	if err != nil {
		return "", fmt.Errorf("git show failed: %w", err)
	}
	if err := os.WriteFile(destPath, content, 0o600); err != nil {
		return "", fmt.Errorf("failed to write temp file: %w", err)
	}
	return destPath, nil
}

func detectASTOutputFile(outputDir string) (string, error) {
	candidates := []string{
		filepath.Join(outputDir, "mixed-ast.json"),
		filepath.Join(outputDir, "go-ast.json"),
		filepath.Join(outputDir, "typescript-ast.json"),
		filepath.Join(outputDir, "python-ast.json"),
	}
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("no AST output file found in %s", outputDir)
}

func callgraphLanguagesFile(outputDir string) string {
	return filepath.Join(outputDir, "callgraph-languages.json")
}

func writeCallgraphLanguageFile(outputDir string, languages []string) error {
	if len(languages) == 0 {
		return fmt.Errorf("no callgraph languages provided")
	}
	payload := struct {
		Languages []string `json:"languages"`
	}{Languages: languages}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return os.WriteFile(callgraphLanguagesFile(outputDir), data, 0o600)
}

func languagesForCallgraph(outputDir string) ([]string, error) {
	scopeData, err := readScopeJSON(outputDir)
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool)
	for _, lang := range scopeData.Languages {
		normalized := normalizeCallgraphLanguage(lang)
		if normalized != "" {
			set[normalized] = true
		}
	}
	if len(set) == 0 && scopeData.Language != "" {
		normalized := normalizeCallgraphLanguage(scopeData.Language)
		if normalized != "" {
			set[normalized] = true
		}
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("no supported languages detected for callgraph")
	}
	languages := make([]string, 0, len(set))
	for lang := range set {
		languages = append(languages, lang)
	}
	orderCallgraphLanguages(languages)
	return languages, nil
}

func normalizeCallgraphLanguage(lang string) string {
	normalizedInput := strings.ToLower(strings.TrimSpace(lang))
	if normalizedInput == "" || normalizedInput == "mixed" || normalizedInput == "unknown" {
		return ""
	}
	if normalized := callgraph.NormalizeLanguage(normalizedInput); normalized != "" {
		return normalized
	}
	return normalizedInput
}

func orderCallgraphLanguages(languages []string) {
	priority := map[string]int{"go": 0, "typescript": 1, "python": 2}
	sort.SliceStable(languages, func(i, j int) bool {
		pi, okI := priority[languages[i]]
		if !okI {
			pi = len(priority) + 1
		}
		pj, okJ := priority[languages[j]]
		if !okJ {
			pj = len(priority) + 1
		}
		if pi != pj {
			return pi < pj
		}
		return languages[i] < languages[j]
	})
}

func writeASTOutputsByLanguage(outputDir string, payload []byte, defaultLanguage string) ([]string, error) {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty AST payload")
	}

	var docs []map[string]interface{}
	if err := json.Unmarshal(trimmed, &docs); err != nil {
		var single map[string]interface{}
		if errSingle := json.Unmarshal(trimmed, &single); errSingle != nil {
			return nil, fmt.Errorf("invalid AST payload: %w", err)
		}
		docs = []map[string]interface{}{single}
	}

	byLanguage := make(map[string][]map[string]interface{})
	for _, doc := range docs {
		lang := sanitizedASTLanguageToken(doc, defaultLanguage)
		byLanguage[lang] = append(byLanguage[lang], doc)
	}

	written := make([]string, 0, len(byLanguage)+1)
	mixedPayload, err := json.MarshalIndent(docs, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal mixed AST payload: %w", err)
	}
	mixedPath := filepath.Join(outputDir, "mixed-ast.json")
	if err := os.WriteFile(mixedPath, mixedPayload, 0o600); err != nil {
		return nil, fmt.Errorf("failed to write %s: %w", mixedPath, err)
	}
	written = append(written, mixedPath)

	for language, docsForLang := range byLanguage {
		astOutputPath := filepath.Join(outputDir, fmt.Sprintf("%s-ast.json", language))
		languagePayload, err := json.MarshalIndent(docsForLang, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal %s AST payload: %w", language, err)
		}
		if err := os.WriteFile(astOutputPath, languagePayload, 0o600); err != nil {
			return nil, fmt.Errorf("failed to write %s: %w", astOutputPath, err)
		}
		written = append(written, astOutputPath)
	}

	return written, nil
}

var astLanguageTokenPattern = regexp.MustCompile(`^[a-z0-9_-]+$`)

func sanitizedASTLanguageToken(doc map[string]interface{}, defaultLanguage string) string {
	candidates := []string{}
	if raw, ok := doc["language"].(string); ok {
		candidates = append(candidates, raw)
	}
	candidates = append(candidates, defaultLanguage)

	for _, candidate := range candidates {
		normalized := normalizeCallgraphLanguage(candidate)
		if normalized == "" {
			continue
		}
		normalized = strings.ToLower(strings.TrimSpace(normalized))
		if astLanguageTokenPattern.MatchString(normalized) {
			return normalized
		}
	}

	return "unknown"
}
