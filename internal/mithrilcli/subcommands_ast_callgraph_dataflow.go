package mithrilcli

import (
	"context"
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
	"time"

	"github.com/lerianstudio/mithril/internal/ast"
	"github.com/lerianstudio/mithril/internal/callgraph"
	"github.com/lerianstudio/mithril/internal/dataflow"
	"github.com/lerianstudio/mithril/internal/fileutil"
	"github.com/lerianstudio/mithril/internal/output"
	scopepkg "github.com/lerianstudio/mithril/internal/scope"
)

func runAstExtractor(args []string, stdout io.Writer, stderr io.Writer) error {
	fs := flag.NewFlagSet("ast-extractor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	beforeFile := fs.String("before", "", "Path to before version")
	afterFile := fs.String("after", "", "Path to after version")
	language := fs.String("lang", "", "Force language (go, typescript, python)")
	outputFmt := fs.String("output", "json", "Output format: json or markdown")
	scriptDir := fs.String("scripts", "", "Directory containing language scripts")
	timeout := fs.Duration("timeout", 30*time.Second, "Extraction timeout")
	batchFile := fs.String("batch", "", "JSON file with batch of file pairs to process")
	verbose := fs.Bool("v", false, "Enable verbose output")
	fs.BoolVar(verbose, "verbose", false, "Enable verbose output")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	scriptsPath := *scriptDir
	if scriptsPath == "" {
		exe, err := os.Executable()
		if err == nil {
			scriptsPath = filepath.Join(filepath.Dir(exe), "..", "..")
		} else {
			scriptsPath = "."
		}
	}
	if err := validateScriptsDir(scriptsPath, *scriptDir == ""); err != nil {
		return fmt.Errorf("scripts directory validation failed: %w", err)
	}

	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}
	validator, err := ast.NewPathValidator(workDir)
	if err != nil {
		return fmt.Errorf("failed to initialize path validator: %w", err)
	}

	if *beforeFile != "" {
		validated, validateErr := validator.ValidatePath(*beforeFile)
		if validateErr != nil {
			return fmt.Errorf("invalid before file path: %w", validateErr)
		}
		*beforeFile = validated
	}
	if *afterFile != "" {
		validated, validateErr := validator.ValidatePath(*afterFile)
		if validateErr != nil {
			return fmt.Errorf("invalid after file path: %w", validateErr)
		}
		*afterFile = validated
	}
	if *batchFile != "" {
		validated, validateErr := validator.ValidatePath(*batchFile)
		if validateErr != nil {
			return fmt.Errorf("invalid batch file path: %w", validateErr)
		}
		*batchFile = validated
	}

	registry := ast.NewRegistry()
	registry.Register(ast.NewGoExtractor())
	registry.Register(ast.NewTypeScriptExtractor(scriptsPath))
	registry.Register(ast.NewPythonExtractor(scriptsPath))

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if *batchFile != "" {
		diffs, err := processASTBatch(ctx, registry, *batchFile)
		if err != nil {
			return err
		}
		if *outputFmt == "markdown" {
			_, _ = fmt.Fprint(stdout, ast.RenderMultipleMarkdown(diffs))
			return nil
		}
		payload, err := json.MarshalIndent(diffs, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal output: %w", err)
		}
		_, _ = fmt.Fprintln(stdout, string(payload))
		return nil
	}

	if *beforeFile == "" && *afterFile == "" {
		return fmt.Errorf("either -before, -after, or -batch must be specified")
	}
	filePath := *afterFile
	if filePath == "" {
		filePath = *beforeFile
	}

	var extractor ast.Extractor
	if *language != "" {
		extractor, err = getExtractorByLanguage(*language, scriptsPath)
	} else {
		extractor, err = registry.GetExtractor(filePath)
	}
	if err != nil {
		return fmt.Errorf("failed to get extractor: %w", err)
	}
	if *verbose {
		_, _ = fmt.Fprintf(stderr, "Using extractor: %s\n", extractor.Language())
	}
	diff, err := extractor.ExtractDiff(ctx, *beforeFile, *afterFile)
	if err != nil {
		return fmt.Errorf("extraction failed: %w", err)
	}

	if *outputFmt == "markdown" {
		_, _ = fmt.Fprint(stdout, ast.RenderMarkdown(diff))
		return nil
	}
	jsonPayload, err := ast.RenderJSON(diff)
	if err != nil {
		return fmt.Errorf("failed to marshal output: %w", err)
	}
	_, _ = fmt.Fprintln(stdout, string(jsonPayload))
	return nil
}

func runCallGraph(args []string, stdout io.Writer, stderr io.Writer) error {
	fs := flag.NewFlagSet("call-graph", flag.ContinueOnError)
	fs.SetOutput(stderr)
	astFile := fs.String("ast", "", "Path to {lang}-ast.json")
	outputDir := fs.String("output", ".ring/codereview", "Output directory")
	timeout := fs.Int("timeout", 30, "Time budget in seconds, 0 = no limit")
	language := fs.String("lang", "", "Language override")
	languagesFile := fs.String("languages-file", "", "Path to JSON file listing languages")
	outputSuffix := fs.String("output-suffix", "", "Suffix to append to output directory")
	verbose := fs.Bool("v", false, "Enable verbose output")
	fs.BoolVar(verbose, "verbose", false, "Enable verbose output")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *astFile == "" {
		return fmt.Errorf("-ast flag is required")
	}
	validatedAST, err := fileutil.ValidatePath(*astFile, ".")
	if err != nil {
		return fmt.Errorf("invalid AST file path: %w", err)
	}
	*astFile = validatedAST
	validatedOutput, err := fileutil.ValidatePath(*outputDir, ".")
	if err != nil {
		return fmt.Errorf("invalid output directory: %w", err)
	}
	*outputDir = validatedOutput

	data, err := fileutil.ReadJSONFileWithLimit(*astFile)
	if err != nil {
		return fmt.Errorf("failed to read AST file: %w", err)
	}
	var diffs []semanticDiff
	if errArray := json.Unmarshal(data, &diffs); errArray != nil {
		var single semanticDiff
		if errSingle := json.Unmarshal(data, &single); errSingle != nil {
			return fmt.Errorf("failed to parse AST payload: %w", errors.Join(errArray, errSingle))
		}
		diffs = []semanticDiff{single}
	}

	languages := []string{}
	if *language != "" {
		languages = append(languages, *language)
	}
	if *languagesFile != "" {
		fileLangs, err := readLanguagesFileForCallgraph(*languagesFile)
		if err != nil {
			return err
		}
		languages = append(languages, fileLangs...)
	}
	if len(languages) == 0 {
		languages = append(languages, detectCallgraphLanguage(*astFile))
	}
	if len(languages) == 0 || languages[0] == "" {
		languages = extractLanguagesFromDiffs(diffs)
	}
	languages = normalizeLanguages(languages)
	if len(languages) == 0 {
		return fmt.Errorf("could not detect language from AST data, use -lang flag")
	}

	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	var runErr error
	for _, lang := range languages {
		langDiffs := filterDiffsByLanguage(diffs, lang)
		if err := runCallgraphForLanguage(lang, langDiffs, workDir, *outputDir, *astFile, *timeout, *outputSuffix, *verbose, stdout, stderr); err != nil {
			runErr = errors.Join(runErr, err)
		}
	}
	return runErr
}

func runDataFlow(args []string, stdout io.Writer, stderr io.Writer) error {
	fs := flag.NewFlagSet("data-flow", flag.ContinueOnError)
	fs.SetOutput(stderr)
	scopePath := fs.String("scope", "scope.json", "Path to scope.json")
	outputDir := fs.String("output", ".", "Output directory for results")
	scriptDir := fs.String("scripts", "", "Path to scripts directory")
	language := fs.String("lang", "", "Analyze specific language only")
	jsonOnly := fs.Bool("json", false, "Output JSON only")
	verbose := fs.Bool("v", false, "Verbose output")
	fs.BoolVar(verbose, "verbose", false, "Verbose output")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}
	scriptsDir := *scriptDir
	if scriptsDir == "" {
		execPath, execErr := os.Executable()
		if execErr == nil {
			scriptsDir = filepath.Dir(filepath.Dir(execPath))
		}
		if scriptsDir == "" {
			scriptsDir = "."
		}
	}

	scopeData, err := loadScopeForDataFlow(*scopePath, workDir)
	if err != nil {
		return fmt.Errorf("failed to load scope: %w", err)
	}

	langs := []string{"go", "python", "typescript"}
	if *language != "" {
		normalized := normalizeDataFlowLanguage(*language)
		if normalized == "" {
			return fmt.Errorf("unsupported language: %s (supported: go, python, typescript)", *language)
		}
		langs = []string{normalized}
	}

	results := make(map[string]*dataflow.FlowAnalysis)
	for _, lang := range langs {
		files := getFilesForLanguage(scopeData, lang)
		if len(files) == 0 {
			continue
		}
		var analyzer dataflow.Analyzer
		switch lang {
		case "go":
			analyzer = dataflow.NewGoAnalyzer(workDir)
		case "python":
			analyzer = dataflow.NewPythonAnalyzer(scriptsDir)
		case "typescript":
			analyzer = dataflow.NewTypeScriptAnalyzer(scriptsDir)
		}
		analysis, analyzeErr := analyzer.Analyze(files)
		if analyzeErr != nil {
			if *verbose {
				_, _ = fmt.Fprintf(stderr, "Warning: %s analysis failed: %v\n", lang, analyzeErr)
			}
			continue
		}
		results[lang] = analysis
		if err := writeJSON(filepath.Join(*outputDir, fmt.Sprintf("%s-flow.json", lang)), analysis); err != nil {
			return fmt.Errorf("failed to write %s results: %w", lang, err)
		}
	}

	if *jsonOnly {
		payload, err := json.MarshalIndent(struct {
			Languages map[string]*dataflow.FlowAnalysis `json:"languages"`
		}{Languages: results}, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal results: %w", err)
		}
		_, _ = fmt.Fprintln(stdout, string(payload))
		return nil
	}

	summary := dataflow.GenerateSecuritySummary(results)
	summaryPath := filepath.Join(*outputDir, "security-summary.md")
	if err := os.WriteFile(summaryPath, []byte(summary), 0o600); err != nil {
		return fmt.Errorf("failed to write security summary: %w", err)
	}
	printDataFlowSummary(results, outputDir, stdout)
	return nil
}

func processASTBatch(ctx context.Context, registry *ast.Registry, batchPath string) ([]ast.SemanticDiff, error) {
	data, err := fileutil.ReadJSONFileWithLimit(batchPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read batch file: %w", err)
	}
	var pairs []ast.FilePair
	if err := json.Unmarshal(data, &pairs); err != nil {
		return nil, fmt.Errorf("failed to parse batch file: %w", err)
	}
	if pairs == nil {
		pairs = []ast.FilePair{}
	}
	return registry.ExtractAll(ctx, pairs)
}

func getExtractorByLanguage(lang string, scriptsPath string) (ast.Extractor, error) {
	switch strings.ToLower(lang) {
	case "go", "golang":
		return ast.NewGoExtractor(), nil
	case "ts", "typescript", "javascript", "js":
		return ast.NewTypeScriptExtractor(scriptsPath), nil
	case "py", "python":
		return ast.NewPythonExtractor(scriptsPath), nil
	default:
		return nil, fmt.Errorf("unknown language: %s", lang)
	}
}

func canonicalDir(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("failed to resolve absolute path for %q: %w", path, err)
	}
	realPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("directory does not exist: %s", absPath)
		}
		return "", fmt.Errorf("failed to evaluate symlinks for %q: %w", path, err)
	}
	return realPath, nil
}

func pathWithinBase(path, base string) bool {
	return path == base || strings.HasPrefix(path, base+string(filepath.Separator))
}

func validateScriptsDir(scriptsDir string, enforceBaseRestriction bool) error {
	if scriptsDir == "" {
		return nil
	}
	resolvedScriptsDir, err := canonicalDir(scriptsDir)
	if err != nil {
		return err
	}
	info, err := os.Stat(resolvedScriptsDir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("path is not a directory: %s", resolvedScriptsDir)
	}
	if !enforceBaseRestriction {
		return nil
	}
	allowedBases := make([]string, 0, 2)
	if cwd, err := os.Getwd(); err == nil {
		allowedBases = append(allowedBases, cwd)
	}
	if execPath, err := os.Executable(); err == nil {
		allowedBases = append(allowedBases, filepath.Join(filepath.Dir(execPath), "..", ".."))
	}
	for _, base := range allowedBases {
		resolvedBase, err := canonicalDir(base)
		if err != nil {
			continue
		}
		if pathWithinBase(resolvedScriptsDir, resolvedBase) {
			return nil
		}
	}
	return fmt.Errorf("scripts directory must be within working directory or executable root: %s", scriptsDir)
}

type semanticFuncSig struct {
	Receiver string `json:"receiver,omitempty"`
}

type semanticFunctionDiff struct {
	Name       string           `json:"name"`
	ChangeType string           `json:"change_type"`
	Before     *semanticFuncSig `json:"before,omitempty"`
	After      *semanticFuncSig `json:"after,omitempty"`
}

type semanticDiff struct {
	Language  string                 `json:"language"`
	FilePath  string                 `json:"file_path"`
	Functions []semanticFunctionDiff `json:"functions"`
}

type languagesPayload struct {
	Languages []string `json:"languages"`
}

func readLanguagesFileForCallgraph(path string) ([]string, error) {
	validated, err := fileutil.ValidatePath(path, ".")
	if err != nil {
		return nil, fmt.Errorf("invalid languages file path: %w", err)
	}
	data, err := fileutil.ReadJSONFileWithLimit(validated)
	if err != nil {
		return nil, fmt.Errorf("failed to read languages file: %w", err)
	}
	var payload languagesPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse languages file: %w", err)
	}
	if payload.Languages == nil {
		return []string{}, nil
	}
	return payload.Languages, nil
}

func detectCallgraphLanguage(filename string) string {
	base := strings.ToLower(filepath.Base(filename))
	if strings.HasPrefix(base, "go-") || strings.HasPrefix(base, "golang-") {
		return callgraph.LangGo
	}
	if strings.HasPrefix(base, "ts-") || strings.HasPrefix(base, "typescript-") {
		return callgraph.LangTypeScript
	}
	if strings.HasPrefix(base, "py-") || strings.HasPrefix(base, "python-") {
		return callgraph.LangPython
	}
	return ""
}

func extractLanguagesFromDiffs(diffs []semanticDiff) []string {
	if len(diffs) == 0 {
		return []string{}
	}
	counts := make(map[string]int)
	for _, diff := range diffs {
		lang := callgraph.NormalizeLanguage(diff.Language)
		if lang != "" && callgraph.IsSupported(lang) {
			counts[lang]++
		}
	}
	priority := []string{callgraph.LangGo, callgraph.LangTypeScript, callgraph.LangPython}
	ordered := make([]string, 0, len(counts))
	for _, lang := range priority {
		if counts[lang] > 0 {
			ordered = append(ordered, lang)
		}
	}
	return ordered
}

func normalizeLanguages(languages []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(languages))
	for _, lang := range languages {
		normalized := callgraph.NormalizeLanguage(lang)
		if normalized == "" || !callgraph.IsSupported(normalized) {
			continue
		}
		if !seen[normalized] {
			seen[normalized] = true
			result = append(result, normalized)
		}
	}
	return result
}

func filterDiffsByLanguage(diffs []semanticDiff, lang string) []semanticDiff {
	normalized := callgraph.NormalizeLanguage(lang)
	if normalized == "" {
		return diffs
	}
	filtered := make([]semanticDiff, 0, len(diffs))
	for _, diff := range diffs {
		if callgraph.NormalizeLanguage(diff.Language) == normalized {
			filtered = append(filtered, diff)
		}
	}
	return filtered
}

func runCallgraphForLanguage(lang string, diffs []semanticDiff, workDir, outputDir, astFile string, timeout int, suffix string, verbose bool, stdout io.Writer, stderr io.Writer) error {
	lang = callgraph.NormalizeLanguage(lang)
	if lang == "" {
		return fmt.Errorf("invalid language")
	}
	if suffix != "" {
		outputDir = strings.TrimRight(outputDir, string(os.PathSeparator)) + suffix
	}
	if verbose {
		_, _ = fmt.Fprintf(stderr, "AST input: %s\n", astFile)
		_, _ = fmt.Fprintf(stderr, "Language: %s\n", lang)
	}
	modifiedFuncs := buildModifiedFunctions(diffs)
	if len(modifiedFuncs) == 0 {
		result := &callgraph.CallGraphResult{Language: lang, ModifiedFunctions: []callgraph.FunctionCallGraph{}, ImpactAnalysis: callgraph.ImpactAnalysis{AffectedPackages: []string{}}}
		return writeResultsWithOutputDir(result, outputDir, stdout)
	}
	analyzer, err := callgraph.NewAnalyzer(lang, workDir)
	if err != nil {
		return err
	}
	result, err := analyzer.Analyze(modifiedFuncs, timeout)
	if err != nil {
		return err
	}
	return writeResultsWithOutputDir(result, outputDir, stdout)
}

func buildModifiedFunctions(diffs []semanticDiff) []callgraph.ModifiedFunction {
	var funcs []callgraph.ModifiedFunction
	for _, diff := range diffs {
		for _, f := range diff.Functions {
			if f.ChangeType == "removed" {
				continue
			}
			receiver := ""
			if f.After != nil && f.After.Receiver != "" {
				receiver = f.After.Receiver
			} else if f.Before != nil && f.Before.Receiver != "" {
				receiver = f.Before.Receiver
			}
			funcs = append(funcs, callgraph.ModifiedFunction{Name: f.Name, File: diff.FilePath, Package: extractPackageFromPath(diff.FilePath), Receiver: receiver})
		}
	}
	return funcs
}

func extractPackageFromPath(filePath string) string {
	dir := filepath.Dir(filepath.Clean(filePath))
	if dir == "." || dir == "" {
		return "main"
	}
	if filepath.IsAbs(dir) {
		return filepath.Base(dir)
	}
	return filepath.ToSlash(dir)
}

var safeSummaryLanguagePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func writeResultsWithOutputDir(result *callgraph.CallGraphResult, outputDir string, stdout io.Writer) error {
	if err := output.WriteJSON(result, outputDir); err != nil {
		return fmt.Errorf("failed to write JSON output: %w", err)
	}
	if err := output.WriteImpactSummary(result, outputDir); err != nil {
		return fmt.Errorf("failed to write markdown output: %w", err)
	}
	language := strings.TrimSpace(result.Language)
	if safeSummaryLanguagePattern.MatchString(language) {
		summaryPath := filepath.Join(outputDir, fmt.Sprintf("impact-summary-%s.md", language))
		if err := os.WriteFile(summaryPath, []byte(output.RenderImpactSummary(result)), 0o600); err != nil {
			return fmt.Errorf("failed to write %s: %w", summaryPath, err)
		}
	}
	_, _ = fmt.Fprintf(stdout, "Call graph analysis complete:\n")
	_, _ = fmt.Fprintf(stdout, "  Language: %s\n", result.Language)
	_, _ = fmt.Fprintf(stdout, "  Functions analyzed: %d\n", len(result.ModifiedFunctions))
	_, _ = fmt.Fprintf(stdout, "  Output: %s/%s-calls.json\n", outputDir, result.Language)
	return nil
}

type scopeFile struct {
	Files           []string
	Languages       []string
	FilesByLanguage map[string][]string
}

type filesNested struct {
	Modified []string `json:"modified"`
	Added    []string `json:"added"`
	Deleted  []string `json:"deleted"`
}

const maxFiles = 10000

func loadScopeForDataFlow(path, workDir string) (*scopeFile, error) {
	canonicalScope, err := scopepkg.ReadScopeJSON(path)
	if err == nil {
		return buildScopeFromCanonical(canonicalScope, workDir)
	}
	return loadLegacyScope(path, workDir)
}

func buildScopeFromCanonical(canonical *scopepkg.ScopeJSON, workDir string) (*scopeFile, error) {
	s := &scopeFile{Languages: []string{}, FilesByLanguage: map[string][]string{}}
	rawFiles := canonical.GetAllFiles()
	if len(rawFiles) > maxFiles {
		return nil, fmt.Errorf("too many files: %d (max %d)", len(rawFiles), maxFiles)
	}
	for _, f := range rawFiles {
		validPath, err := validateFilePath(workDir, f)
		if err != nil {
			return nil, err
		}
		s.Files = append(s.Files, validPath)
	}
	seen := map[string]struct{}{}
	for _, lang := range canonical.Languages {
		normalized := normalizeDataFlowLanguage(lang)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		s.Languages = append(s.Languages, normalized)
	}
	for _, file := range s.Files {
		lang := detectDataFlowLanguage(file)
		if lang != "" {
			s.FilesByLanguage[lang] = append(s.FilesByLanguage[lang], file)
		}
	}
	return s, nil
}

func loadLegacyScope(path, workDir string) (*scopeFile, error) {
	data, err := fileutil.ReadJSONFileWithLimit(path)
	if err != nil {
		return nil, err
	}
	s := &scopeFile{Languages: []string{}, FilesByLanguage: map[string][]string{}}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	var rawFiles []string
	if filesRaw, ok := raw["files"]; ok {
		var flat []string
		if err := json.Unmarshal(filesRaw, &flat); err == nil {
			rawFiles = flat
		} else {
			var nested filesNested
			if err := json.Unmarshal(filesRaw, &nested); err == nil {
				rawFiles = append(rawFiles, nested.Modified...)
				rawFiles = append(rawFiles, nested.Added...)
			}
		}
	}
	for _, f := range rawFiles {
		validPath, err := validateFilePath(workDir, f)
		if err != nil {
			return nil, err
		}
		s.Files = append(s.Files, validPath)
	}
	for _, file := range s.Files {
		if lang := detectDataFlowLanguage(file); lang != "" {
			s.FilesByLanguage[lang] = append(s.FilesByLanguage[lang], file)
		}
	}
	for lang := range s.FilesByLanguage {
		s.Languages = append(s.Languages, lang)
	}
	sort.Strings(s.Languages)
	return s, nil
}

func validateFilePath(basePath, filePath string) (string, error) {
	validator, err := ast.NewPathValidator(basePath)
	if err != nil {
		return "", err
	}
	candidate := filePath
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(basePath, candidate)
	}
	validated, err := validator.ValidatePath(candidate)
	if err != nil {
		return "", err
	}
	if filepath.IsAbs(validated) {
		rel, err := filepath.Rel(basePath, validated)
		if err == nil {
			validated = rel
		}
	}
	return filepath.Clean(validated), nil
}

func detectDataFlowLanguage(file string) string {
	switch strings.ToLower(filepath.Ext(file)) {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".ts", ".tsx", ".js", ".jsx":
		return "typescript"
	default:
		return ""
	}
}

func normalizeDataFlowLanguage(lang string) string {
	normalized := string(scopepkg.NormalizeLanguage(lang))
	if normalized == "mixed" {
		return ""
	}
	return normalized
}

func getFilesForLanguage(scope *scopeFile, lang string) []string {
	if files, ok := scope.FilesByLanguage[lang]; ok && len(files) > 0 {
		return files
	}
	filtered := make([]string, 0)
	for _, file := range scope.Files {
		if detectDataFlowLanguage(file) == lang {
			filtered = append(filtered, file)
		}
	}
	return filtered
}

func writeJSON(path string, data interface{}) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, payload, 0o600)
}

func printDataFlowSummary(results map[string]*dataflow.FlowAnalysis, outputDir *string, stdout io.Writer) {
	langs := make([]string, 0, len(results))
	for lang := range results {
		langs = append(langs, lang)
	}
	_, _ = fmt.Fprintf(stdout, "Data flow analysis complete:\n")
	_, _ = fmt.Fprintf(stdout, "  Languages analyzed: %d (%s)\n", len(langs), strings.Join(langs, ", "))
	_, _ = fmt.Fprintf(stdout, "  Output: %s/{lang}-flow.json\n", *outputDir)
	_, _ = fmt.Fprintf(stdout, "  Summary: %s/security-summary.md\n", *outputDir)
}
