package context

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	cgpkg "github.com/lerianstudio/mithril/internal/callgraph"
	"github.com/lerianstudio/mithril/internal/fileutil"
	scopepkg "github.com/lerianstudio/mithril/internal/scope"
)

// highImpactCallerThreshold is the minimum number of callers for a function
// to be considered high-impact. Re-exported from callgraph so the context
// builders share a single threshold with the markdown writer.
const highImpactCallerThreshold = cgpkg.HighImpactCallerThreshold

// reviewerDataBuilder populates template data for a specific reviewer.
// Builders are pure functions over the phase outputs — they do not need
// *Compiler state (H25).
type reviewerDataBuilder func(data *TemplateData, outputs *PhaseOutputs)

// reviewerDataBuilders maps reviewer names to their data builder functions.
var reviewerDataBuilders = map[string]reviewerDataBuilder{
	"code-reviewer":           buildCodeReviewerData,
	"security-reviewer":       buildSecurityReviewerData,
	"business-logic-reviewer": buildBusinessLogicReviewerData,
	"test-reviewer":           buildTestReviewerData,
	"nil-safety-reviewer":     buildNilSafetyReviewerData,
	"consequences-reviewer":   buildConsequencesReviewerData,
	"dead-code-reviewer":      buildDeadCodeReviewerData,
}

func hasReviewerDataBuilder(reviewer string) bool {
	_, ok := reviewerDataBuilders[reviewer]
	return ok
}

// Compiler aggregates phase outputs and generates reviewer context files.
type Compiler struct {
	inputDir  string
	outputDir string
	language  string
}

// validatePath validates a directory path for security.
// It prevents path traversal attacks and optionally verifies the directory exists.
func validatePath(path string, mustExist bool) error {
	validated, err := fileutil.ValidatePath(path, ".")
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	if mustExist {
		info, err := os.Stat(validated)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("path does not exist: %s", validated)
			}
			return fmt.Errorf("failed to stat path: %w", err)
		}
		if !info.IsDir() {
			return fmt.Errorf("path is not a directory: %s", validated)
		}
	}

	return nil
}

// readJSONFileWithLimit reads a JSON file with a size limit to prevent resource exhaustion.
func readJSONFileWithLimit(path string) ([]byte, error) {
	return fileutil.ReadJSONFileWithLimit(path)
}

// NewCompiler creates a new context compiler with input/output validation.
// inputDir: directory containing phase outputs (e.g., .ring/codereview/)
// outputDir: directory to write context files (typically same as inputDir)
func NewCompiler(inputDir, outputDir string) (*Compiler, error) {
	return NewCompilerWithValidation(inputDir, outputDir)
}

// NewCompilerWithValidation creates a new context compiler with path validation.
// inputDir: directory containing phase outputs (e.g., .ring/codereview/)
// outputDir: directory to write context files (typically same as inputDir)
// Returns an error if paths contain traversal sequences or are invalid.
func NewCompilerWithValidation(inputDir, outputDir string) (*Compiler, error) {
	// Validate input directory (must exist since we read from it)
	if err := validatePath(inputDir, true); err != nil {
		return nil, fmt.Errorf("invalid input directory: %w", err)
	}

	// Validate output directory (may not exist yet, will be created)
	if err := validatePath(outputDir, false); err != nil {
		return nil, fmt.Errorf("invalid output directory: %w", err)
	}

	return &Compiler{
		inputDir:  inputDir,
		outputDir: outputDir,
	}, nil
}

// Compile reads all phase outputs and generates reviewer context files.
// Per-phase failures are logged and degrade to empty data for the affected
// phase so one corrupt input can no longer wipe every reviewer context
// (H23). Errors are still surfaced via outputs.Errors for observability.
func (c *Compiler) Compile() error {
	if err := reviewerConfigurationError(); err != nil {
		return fmt.Errorf("reviewer configuration invalid: %w", err)
	}

	outputs, err := c.readPhaseOutputs()
	if err != nil {
		return fmt.Errorf("failed to read phase outputs: %w", err)
	}
	for _, e := range outputs.Errors {
		log.Printf("context compile: phase degraded — %s", e)
	}

	// Determine language from scope
	if outputs.Scope != nil {
		c.language = outputs.Scope.Language
	}

	// Generate context for each reviewer
	reviewers := GetReviewerNames()
	for _, reviewer := range reviewers {
		if err := c.generateReviewerContext(reviewer, outputs); err != nil {
			return fmt.Errorf("failed to generate context for %s: %w", reviewer, err)
		}
	}

	return nil
}

// Phase name constants used as keys in PhaseOutputs.PhaseStatus. Each one
// distinguishes between "file absent", "parse/read failed", "ran but empty",
// and "completed with data" (H24).
const (
	phaseScope          = "scope"
	phaseStaticAnalysis = "static_analysis"
	phaseAST            = "ast"
	phaseCallGraph      = "call_graph"
	phaseDataFlow       = "data_flow"
)

// readPhaseOutputs reads all phase outputs from the input directory.
// It tracks per-phase status so downstream reviewers can distinguish
// "phase did not run" from "phase ran and found nothing" (H24), and
// failures in one phase no longer wipe output for other phases (H23).
func (c *Compiler) readPhaseOutputs() (*PhaseOutputs, error) {
	outputs := &PhaseOutputs{PhaseStatus: map[string]PhaseStatus{}}

	// Phase 0: scope.json
	scopePath := filepath.Join(c.inputDir, "scope.json")
	if canonicalScope, err := scopepkg.ReadScopeJSON(scopePath); err == nil {
		scopeData := ScopeData{
			BaseRef:   canonicalScope.BaseRef,
			HeadRef:   canonicalScope.HeadRef,
			Language:  canonicalScope.Language,
			Languages: append([]string{}, canonicalScope.Languages...),
			Files: ScopeFiles{
				Modified: canonicalScope.Files.Modified,
				Added:    canonicalScope.Files.Added,
				Deleted:  canonicalScope.Files.Deleted,
			},
			Stats:            ScopeStats(canonicalScope.Stats),
			PackagesAffected: append([]string{}, canonicalScope.Packages...),
		}
		if scopeData.Languages == nil {
			scopeData.Languages = []string{}
		}
		outputs.Scope = &scopeData
		outputs.PhaseStatus[phaseScope] = PhaseStatusCompleted
	} else if isFileNotFound(err) {
		outputs.PhaseStatus[phaseScope] = PhaseStatusNotRun
	} else {
		outputs.PhaseStatus[phaseScope] = PhaseStatusFailed
		outputs.Errors = append(outputs.Errors, "scope.json read error")
	}

	// Phase 1: static-analysis.json
	staticPath := filepath.Join(c.inputDir, "static-analysis.json")
	if data, err := readJSONFileWithLimit(staticPath); err == nil {
		var static StaticAnalysisData
		if parseErr := json.Unmarshal(data, &static); parseErr == nil {
			outputs.StaticAnalysis = &static
			if len(static.Findings) == 0 {
				outputs.PhaseStatus[phaseStaticAnalysis] = PhaseStatusEmpty
			} else {
				outputs.PhaseStatus[phaseStaticAnalysis] = PhaseStatusCompleted
			}
		} else {
			outputs.PhaseStatus[phaseStaticAnalysis] = PhaseStatusFailed
			outputs.Errors = append(outputs.Errors, "static-analysis.json parse error")
		}
	} else if isFileNotFound(err) {
		outputs.PhaseStatus[phaseStaticAnalysis] = PhaseStatusNotRun
	} else {
		outputs.PhaseStatus[phaseStaticAnalysis] = PhaseStatusFailed
		outputs.Errors = append(outputs.Errors, "static-analysis.json read error")
	}

	// Phases 2-4: language-aware scan. We iterate languages and pick the first
	// successful parse per phase as the primary output (matching legacy
	// behaviour). Each phase gets a single aggregate status: Completed if any
	// language parsed, Failed if all attempts errored, NotRun if no file for
	// any language existed, Empty if it parsed but produced nothing.
	langs := c.languagesFromScope(outputs.Scope)

	outputs.PhaseStatus[phaseAST] = loadPhasePerLanguage(c.inputDir, langs, "-ast.json", func(data []byte) (bool, error) {
		astData, err := parseASTData(data)
		if err != nil {
			return false, err
		}
		if outputs.AST == nil {
			outputs.AST = astData
		}
		return astData != nil, nil
	}, func(msg string) { outputs.Errors = append(outputs.Errors, msg) })
	if outputs.PhaseStatus[phaseAST] == PhaseStatusCompleted && astIsEmpty(outputs.AST) {
		outputs.PhaseStatus[phaseAST] = PhaseStatusEmpty
	}

	outputs.PhaseStatus[phaseCallGraph] = loadPhasePerLanguage(c.inputDir, langs, "-calls.json", func(data []byte) (bool, error) {
		var calls CallGraphData
		if err := json.Unmarshal(data, &calls); err != nil {
			return false, err
		}
		if outputs.CallGraph == nil {
			outputs.CallGraph = &calls
		}
		return true, nil
	}, func(msg string) { outputs.Errors = append(outputs.Errors, msg) })
	if outputs.PhaseStatus[phaseCallGraph] == PhaseStatusCompleted && outputs.CallGraph != nil && len(outputs.CallGraph.ModifiedFunctions) == 0 {
		outputs.PhaseStatus[phaseCallGraph] = PhaseStatusEmpty
	}

	outputs.PhaseStatus[phaseDataFlow] = loadPhasePerLanguage(c.inputDir, langs, "-flow.json", func(data []byte) (bool, error) {
		flowData, err := parseDataFlowData(data)
		if err != nil {
			return false, err
		}
		if outputs.DataFlow == nil {
			outputs.DataFlow = flowData
		}
		return flowData != nil, nil
	}, func(msg string) { outputs.Errors = append(outputs.Errors, msg) })
	if outputs.PhaseStatus[phaseDataFlow] == PhaseStatusCompleted && outputs.DataFlow != nil &&
		len(outputs.DataFlow.Flows) == 0 && len(outputs.DataFlow.NilSources) == 0 {
		outputs.PhaseStatus[phaseDataFlow] = PhaseStatusEmpty
	}

	return outputs, nil
}

// loadPhasePerLanguage walks the supplied languages, reads each
// "<lang><suffix>" file from dir, and passes the raw bytes to parse. Returns
// the aggregated PhaseStatus across all languages. Errors are funnelled into
// recordErr so the caller can log or accumulate as it sees fit.
func loadPhasePerLanguage(
	dir string,
	languages []string,
	suffix string,
	parse func([]byte) (bool, error),
	recordErr func(string),
) PhaseStatus {
	var (
		anyCompleted bool
		anyFailed    bool
		anyFound     bool
	)
	for _, lang := range languages {
		path := filepath.Join(dir, lang+suffix)
		data, err := readJSONFileWithLimit(path)
		if err != nil {
			if isFileNotFound(err) {
				continue
			}
			anyFailed = true
			anyFound = true
			recordErr(fmt.Sprintf("%s%s read error", lang, suffix))
			continue
		}
		anyFound = true
		if _, perr := parse(data); perr == nil {
			anyCompleted = true
		} else {
			anyFailed = true
			recordErr(fmt.Sprintf("%s%s parse error", lang, suffix))
		}
	}

	switch {
	case anyCompleted:
		return PhaseStatusCompleted
	case anyFailed:
		return PhaseStatusFailed
	case !anyFound:
		return PhaseStatusNotRun
	default:
		return PhaseStatusEmpty
	}
}

func astIsEmpty(a *ASTData) bool {
	if a == nil {
		return true
	}
	return len(a.Functions.Modified) == 0 &&
		len(a.Functions.Added) == 0 &&
		len(a.Functions.Deleted) == 0 &&
		len(a.Types.Modified) == 0 &&
		len(a.Types.Added) == 0 &&
		len(a.Types.Deleted) == 0 &&
		len(a.Imports.Added) == 0 &&
		len(a.Imports.Removed) == 0
}

func isFileNotFound(err error) bool {
	if err == nil {
		return false
	}
	if os.IsNotExist(err) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "no such file or directory")
}

func (c *Compiler) languagesFromScope(scope *ScopeData) []string {
	if scope == nil {
		return []string{"go", "typescript", "python"}
	}

	langs := append([]string{}, scope.Languages...)
	primary := strings.TrimSpace(scope.Language)
	if primary != "" {
		found := false
		for _, lang := range langs {
			if lang == primary {
				found = true
				break
			}
		}
		if !found {
			langs = append(langs, primary)
		}
	}

	if len(langs) == 0 {
		return []string{"go", "typescript", "python"}
	}

	return langs
}

// generateReviewerContext generates the context file for a specific reviewer.
func (c *Compiler) generateReviewerContext(reviewer string, outputs *PhaseOutputs) error {
	// Build template data based on reviewer
	data := c.buildTemplateData(reviewer, outputs)

	// Get and render template
	templateStr, err := GetTemplateForReviewer(reviewer)
	if err != nil {
		return fmt.Errorf("failed to get template: %w", err)
	}

	content, err := RenderTemplate(templateStr, data)
	if err != nil {
		return fmt.Errorf("failed to render template: %w", err)
	}

	// Write context file
	outputPath := filepath.Join(c.outputDir, fmt.Sprintf("context-%s.md", reviewer))
	if err := os.MkdirAll(c.outputDir, 0o700); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	if err := os.WriteFile(outputPath, []byte(content), 0o600); err != nil {
		return fmt.Errorf("failed to write context file: %w", err)
	}

	return nil
}

// buildTemplateData constructs the template data for a specific reviewer.
func (c *Compiler) buildTemplateData(reviewer string, outputs *PhaseOutputs) *TemplateData {
	data := &TemplateData{}
	builder, ok := reviewerDataBuilders[reviewer]
	if !ok {
		data.Findings = []Finding{}
		data.FocusAreas = []FocusArea{{
			Title:       "Unknown reviewer",
			Description: fmt.Sprintf("No template data builder registered for reviewer %s", reviewer),
		}}
		return data
	}
	builder(data, outputs)
	return data
}

// buildCodeReviewerData populates data for the code reviewer.
func buildCodeReviewerData(data *TemplateData, outputs *PhaseOutputs) {
	// Static analysis findings (non-security)
	if outputs.StaticAnalysis != nil {
		data.Findings = FilterFindingsForCodeReviewer(outputs.StaticAnalysis.Findings)
		data.FindingCount = len(data.Findings)
	}

	// Semantic changes from AST
	if outputs.AST != nil {
		data.HasSemanticChanges = true
		data.ModifiedFunctions = outputs.AST.Functions.Modified
		data.AddedFunctions = outputs.AST.Functions.Added
		data.ModifiedTypes = outputs.AST.Types.Modified
	}

	// Build focus areas
	data.FocusAreas = buildCodeReviewerFocusAreas(outputs)
}

// buildSecurityReviewerData populates data for the security reviewer.
func buildSecurityReviewerData(data *TemplateData, outputs *PhaseOutputs) {
	// Security-specific findings
	if outputs.StaticAnalysis != nil {
		data.Findings = FilterFindingsForSecurityReviewer(outputs.StaticAnalysis.Findings)
		data.FindingCount = len(data.Findings)
	}

	// Data flow analysis
	if outputs.DataFlow != nil {
		data.HasDataFlowAnalysis = true
		for _, flow := range outputs.DataFlow.Flows {
			switch flow.Risk {
			case "high", "critical":
				data.HighRiskFlows = append(data.HighRiskFlows, flow)
			case "medium":
				data.MediumRiskFlows = append(data.MediumRiskFlows, flow)
			}
		}
	}

	// Build focus areas
	data.FocusAreas = buildSecurityReviewerFocusAreas(outputs)
}

// buildBusinessLogicReviewerData populates data for the business logic reviewer.
// Also surfaces data-flow findings (H40): a user-input -> database flow is
// a correctness concern (is validation right, is the query appropriate?),
// not purely a security concern. The security reviewer still sees the same
// flows via its own builder — they are complementary, not exclusive.
func buildBusinessLogicReviewerData(data *TemplateData, outputs *PhaseOutputs) {
	// Call graph for impact analysis
	if outputs.CallGraph != nil {
		data.HasCallGraph = true
		data.CallGraphPartialResults = outputs.CallGraph.PartialResults
		data.CallGraphTimeBudgetExceeded = outputs.CallGraph.TimeBudgetExceeded
		data.CallGraphWarnings = append([]string{}, outputs.CallGraph.Warnings...)
		data.HighImpactFunctions = GetHighImpactFunctions(outputs.CallGraph, highImpactCallerThreshold)
	}

	// Semantic changes
	if outputs.AST != nil {
		data.HasSemanticChanges = true
		data.ModifiedFunctions = outputs.AST.Functions.Modified
	}

	// Data-flow correctness signals: high/medium risk flows indicate where
	// validation and query shape matter, independent of pure security risk.
	if outputs.DataFlow != nil {
		for _, flow := range outputs.DataFlow.Flows {
			switch flow.Risk {
			case "high", "critical":
				data.HighRiskFlows = append(data.HighRiskFlows, flow)
			case "medium":
				data.MediumRiskFlows = append(data.MediumRiskFlows, flow)
			}
		}
		if len(data.HighRiskFlows) > 0 || len(data.MediumRiskFlows) > 0 {
			data.HasDataFlowAnalysis = true
		}
	}

	// Build focus areas
	data.FocusAreas = buildBusinessLogicReviewerFocusAreas(outputs, data)
}

// buildTestReviewerData populates data for the test reviewer.
func buildTestReviewerData(data *TemplateData, outputs *PhaseOutputs) {
	// Call graph for test coverage
	if outputs.CallGraph != nil {
		data.HasCallGraph = true
		data.CallGraphPartialResults = outputs.CallGraph.PartialResults
		data.CallGraphTimeBudgetExceeded = outputs.CallGraph.TimeBudgetExceeded
		data.CallGraphWarnings = append([]string{}, outputs.CallGraph.Warnings...)
		// Use AllModifiedFunctionsGraph for template (holds FunctionCallGraph)
		data.AllModifiedFunctionsGraph = outputs.CallGraph.ModifiedFunctions
		data.UncoveredFunctions = GetUncoveredFunctions(outputs.CallGraph)
	}

	// Build focus areas
	data.FocusAreas = buildTestReviewerFocusAreas(outputs)
}

// buildNilSafetyReviewerData populates data for the nil safety reviewer.
func buildNilSafetyReviewerData(data *TemplateData, outputs *PhaseOutputs) {
	// Nil sources from data flow
	if outputs.DataFlow != nil && len(outputs.DataFlow.NilSources) > 0 {
		data.HasNilSources = true
		data.NilSources = outputs.DataFlow.NilSources
		data.HighRiskNilSources = FilterNilSourcesByRisk(outputs.DataFlow.NilSources, "high")
	}

	// Build focus areas
	data.FocusAreas = buildNilSafetyReviewerFocusAreas(outputs)
}

// Focus area builders (package-level — no Compiler state used).

func buildCodeReviewerFocusAreas(outputs *PhaseOutputs) []FocusArea {
	var areas []FocusArea

	// Check for deprecation warnings
	if outputs.StaticAnalysis != nil {
		deprecations := FilterFindingsByCategory(outputs.StaticAnalysis.Findings, "deprecation")
		if len(deprecations) > 0 {
			areas = append(areas, FocusArea{
				Title:       "Deprecated API Usage",
				Description: fmt.Sprintf("%d deprecated API calls need updating", len(deprecations)),
			})
		}
	}

	// Check for signature changes
	if outputs.AST != nil {
		for _, f := range outputs.AST.Functions.Modified {
			if f.Before.Signature != f.After.Signature {
				areas = append(areas, FocusArea{
					Title:       fmt.Sprintf("Signature change in %s", f.Name),
					Description: "Function signature modified - verify caller compatibility",
				})
			}
		}
	}

	return areas
}

func buildSecurityReviewerFocusAreas(outputs *PhaseOutputs) []FocusArea {
	var areas []FocusArea

	// Check for high-risk data flows
	if outputs.DataFlow != nil {
		highRisk := 0
		for _, flow := range outputs.DataFlow.Flows {
			if (flow.Risk == "high" || flow.Risk == "critical") && !flow.Sanitized {
				highRisk++
			}
		}
		if highRisk > 0 {
			areas = append(areas, FocusArea{
				Title:       "Unsanitized High-Risk Flows",
				Description: fmt.Sprintf("%d data flows without sanitization", highRisk),
			})
		}
	}

	// Check for security findings
	if outputs.StaticAnalysis != nil {
		critical := FilterFindingsBySeverity(
			FilterFindingsForSecurityReviewer(outputs.StaticAnalysis.Findings),
			"high",
		)
		if len(critical) > 0 {
			areas = append(areas, FocusArea{
				Title:       "Critical Security Findings",
				Description: fmt.Sprintf("%d high/critical security issues detected", len(critical)),
			})
		}
	}

	return areas
}

func buildBusinessLogicReviewerFocusAreas(outputs *PhaseOutputs, data *TemplateData) []FocusArea {
	var areas []FocusArea

	// Check for high-impact changes
	if outputs.CallGraph != nil {
		highImpact := GetHighImpactFunctions(outputs.CallGraph, highImpactCallerThreshold)
		if len(highImpact) > 0 {
			areas = append(areas, FocusArea{
				Title:       "High-Impact Functions",
				Description: fmt.Sprintf("%d functions with %d+ callers modified", len(highImpact), highImpactCallerThreshold),
			})
		}
	}

	// Check for new functions
	if outputs.AST != nil && len(outputs.AST.Functions.Added) > 0 {
		areas = append(areas, FocusArea{
			Title:       "New Functions",
			Description: fmt.Sprintf("%d new functions added - verify business requirements", len(outputs.AST.Functions.Added)),
		})
	}

	// H40: dataflow correctness focus
	if data != nil && len(data.HighRiskFlows) > 0 {
		areas = append(areas, FocusArea{
			Title:       "Data Flow Correctness",
			Description: fmt.Sprintf("%d high-risk data flow(s) — verify input validation and query shape", len(data.HighRiskFlows)),
		})
	}

	return areas
}

func buildTestReviewerFocusAreas(outputs *PhaseOutputs) []FocusArea {
	var areas []FocusArea

	// Check for uncovered functions
	if outputs.CallGraph != nil {
		uncovered := GetUncoveredFunctions(outputs.CallGraph)
		if len(uncovered) > 0 {
			areas = append(areas, FocusArea{
				Title:       "Uncovered Code",
				Description: fmt.Sprintf("%d modified functions without test coverage", len(uncovered)),
			})
		}
	}

	// Check for new error paths
	if outputs.AST != nil && outputs.AST.ErrorHandling.NewErrorReturns != nil {
		if len(outputs.AST.ErrorHandling.NewErrorReturns) > 0 {
			areas = append(areas, FocusArea{
				Title:       "New Error Paths",
				Description: fmt.Sprintf("%d new error return paths need negative tests", len(outputs.AST.ErrorHandling.NewErrorReturns)),
			})
		}
	}

	return areas
}

func buildNilSafetyReviewerFocusAreas(outputs *PhaseOutputs) []FocusArea {
	var areas []FocusArea

	// Check for unchecked nil sources
	if outputs.DataFlow != nil {
		unchecked := FilterNilSourcesUnchecked(outputs.DataFlow.NilSources)
		if len(unchecked) > 0 {
			areas = append(areas, FocusArea{
				Title:       "Unchecked Nil Sources",
				Description: fmt.Sprintf("%d potential nil values without checks", len(unchecked)),
			})
		}

		// Check for high-risk nil sources
		highRisk := FilterNilSourcesByRisk(outputs.DataFlow.NilSources, "high")
		if len(highRisk) > 0 {
			areas = append(areas, FocusArea{
				Title:       "High-Risk Nil Sources",
				Description: fmt.Sprintf("%d high-risk nil sources require immediate attention", len(highRisk)),
			})
		}
	}

	return areas
}

func buildConsequencesReviewerData(data *TemplateData, outputs *PhaseOutputs) {
	if outputs.AST != nil {
		for _, f := range outputs.AST.Functions.Modified {
			if f.Before.Signature != f.After.Signature {
				data.SignatureChanges = append(data.SignatureChanges, f)
			}
		}
		data.TypeSurfaceChanges = outputs.AST.Types.Modified
		data.ImportsAdded = outputs.AST.Imports.Added
		data.ImportsRemoved = outputs.AST.Imports.Removed
		data.ErrorReturnsAdded = outputs.AST.ErrorHandling.NewErrorReturns
		data.ErrorChecksRemoved = outputs.AST.ErrorHandling.RemovedErrorChecks
	}

	if outputs.CallGraph != nil {
		for _, f := range outputs.CallGraph.ModifiedFunctions {
			if len(f.Callers) > 0 {
				data.CallerImpactedFunctions = append(data.CallerImpactedFunctions, f)
			}
		}
	}

	data.HasConsequences = len(data.SignatureChanges) > 0 ||
		len(data.TypeSurfaceChanges) > 0 ||
		len(data.ImportsAdded) > 0 ||
		len(data.ImportsRemoved) > 0 ||
		len(data.ErrorReturnsAdded) > 0 ||
		len(data.ErrorChecksRemoved) > 0 ||
		len(data.CallerImpactedFunctions) > 0

	data.FocusAreas = buildConsequencesReviewerFocusAreas(outputs, data)
}

func buildDeadCodeReviewerData(data *TemplateData, outputs *PhaseOutputs) {
	if outputs.AST != nil {
		data.DeletedFunctions = outputs.AST.Functions.Deleted
		data.DeletedTypes = outputs.AST.Types.Deleted
		data.RemovedImports = outputs.AST.Imports.Removed
	}

	if outputs.CallGraph != nil {
		for _, f := range outputs.CallGraph.ModifiedFunctions {
			if len(f.Callers) == 0 {
				data.OrphanFunctions = append(data.OrphanFunctions, f)
				if len(f.TestCoverage) > 0 {
					data.ZombieTests = append(data.ZombieTests, f)
				}
			}
		}
	}

	data.HasDeadCodeSignals = len(data.DeletedFunctions) > 0 ||
		len(data.DeletedTypes) > 0 ||
		len(data.RemovedImports) > 0 ||
		len(data.OrphanFunctions) > 0 ||
		len(data.ZombieTests) > 0

	data.FocusAreas = buildDeadCodeReviewerFocusAreas(outputs, data)
}

func buildConsequencesReviewerFocusAreas(outputs *PhaseOutputs, data *TemplateData) []FocusArea {
	var areas []FocusArea

	if len(data.SignatureChanges) > 0 {
		areas = append(areas, FocusArea{
			Title:       "Signature Changes",
			Description: fmt.Sprintf("%d function signature(s) changed - all direct callers must be verified", len(data.SignatureChanges)),
		})
	}
	if len(data.TypeSurfaceChanges) > 0 {
		areas = append(areas, FocusArea{
			Title:       "Type Shape Changes",
			Description: fmt.Sprintf("%d type(s) modified - downstream serialization and field access may break", len(data.TypeSurfaceChanges)),
		})
	}
	if outputs.CallGraph != nil {
		highImpact := GetHighImpactFunctions(outputs.CallGraph, highImpactCallerThreshold)
		if len(highImpact) > 0 {
			areas = append(areas, FocusArea{
				Title:       "Broad Caller Reach",
				Description: fmt.Sprintf("%d modified function(s) have %d+ callers", len(highImpact), highImpactCallerThreshold),
			})
		}
	}
	if len(data.ErrorReturnsAdded) > 0 {
		areas = append(areas, FocusArea{
			Title:       "New Error Paths",
			Description: fmt.Sprintf("%d new error return(s) widen the failure surface for callers", len(data.ErrorReturnsAdded)),
		})
	}

	return areas
}

func buildDeadCodeReviewerFocusAreas(_ *PhaseOutputs, data *TemplateData) []FocusArea {
	var areas []FocusArea

	if len(data.DeletedFunctions) > 0 {
		areas = append(areas, FocusArea{
			Title:       "Deleted Functions",
			Description: fmt.Sprintf("%d function(s) removed - confirm no external consumers remain", len(data.DeletedFunctions)),
		})
	}
	if len(data.OrphanFunctions) > 0 {
		areas = append(areas, FocusArea{
			Title:       "Orphan Functions",
			Description: fmt.Sprintf("%d modified function(s) have zero callers in the call graph", len(data.OrphanFunctions)),
		})
	}
	if len(data.ZombieTests) > 0 {
		areas = append(areas, FocusArea{
			Title:       "Zombie Tests",
			Description: fmt.Sprintf("%d orphan function(s) are still covered by tests - candidates for joint removal", len(data.ZombieTests)),
		})
	}
	if len(data.RemovedImports) > 0 {
		areas = append(areas, FocusArea{
			Title:       "Removed Imports",
			Description: fmt.Sprintf("%d import(s) removed - verify downstream packages still resolve", len(data.RemovedImports)),
		})
	}

	return areas
}
