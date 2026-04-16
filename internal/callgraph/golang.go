package callgraph

import (
	"container/list"
	"context"
	"fmt"
	"go/types"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// Resource protection limits.
const (
	maxModifiedFunctions = 500   // Maximum number of modified functions to analyze
	maxTransitiveCallers = 10000 // Maximum transitive callers before stopping BFS
	defaultTimeBudgetSec = 120   // Default time budget when not specified
)

// GoAnalyzer implements call graph analysis for Go code.
type GoAnalyzer struct {
	workDir        string
	loadPackagesFn func(ctx context.Context, patterns []string) ([]*packages.Package, []string, error)
}

// NewGoAnalyzer creates a new Go call graph analyzer.
// workDir is the root directory for package loading.
func NewGoAnalyzer(workDir string) *GoAnalyzer {
	analyzer := &GoAnalyzer{
		workDir: workDir,
	}
	analyzer.loadPackagesFn = analyzer.loadPackages
	return analyzer
}

// loadPackages loads Go packages from the working directory.
// Returns packages, any warnings encountered, and error if all packages failed to load.
func (g *GoAnalyzer) loadPackages(ctx context.Context, patterns []string) ([]*packages.Package, []string, error) {
	cfg := &packages.Config{
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedCompiledGoFiles |
			packages.NeedImports |
			packages.NeedDeps |
			packages.NeedTypes |
			packages.NeedSyntax |
			packages.NeedTypesInfo,
		Context: ctx,
		Dir:     g.workDir,
		Tests:   true, // Include test packages for test coverage analysis
	}

	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load packages: %w", err)
	}

	// Check for package errors (but don't fail completely)
	var warnings []string
	for _, pkg := range pkgs {
		for _, err := range pkg.Errors {
			warnings = append(warnings, fmt.Sprintf("package %s: %v", pkg.PkgPath, err))
		}
	}

	if len(warnings) > 0 && len(pkgs) == 0 {
		return nil, warnings, fmt.Errorf("all packages failed to load: %v", warnings)
	}

	return pkgs, warnings, nil
}

// buildSSA builds SSA form for the loaded packages.
func (g *GoAnalyzer) buildSSA(pkgs []*packages.Package) *ssa.Program {
	// ssautil.AllPackages also returns an []*ssa.Package (ssaPkgs), but we only need the *ssa.Program for cha.CallGraph.
	prog, _ := ssautil.AllPackages(pkgs, ssa.InstantiateGenerics)
	if prog == nil {
		return nil
	}
	prog.Build()
	return prog
}

// getAffectedPackages extracts unique package paths from modified functions.
func getAffectedPackages(funcs []ModifiedFunction) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)

	for _, fn := range funcs {
		if fn.Package != "" && !seen[fn.Package] {
			seen[fn.Package] = true
			result = append(result, fn.Package)
		}
	}

	return result
}

// Analyze implements the Analyzer interface for Go code.
func (g *GoAnalyzer) Analyze(modifiedFuncs []ModifiedFunction, timeBudgetSec int) (*CallGraphResult, error) {
	result := &CallGraphResult{
		Language:          "go",
		ModifiedFunctions: make([]FunctionCallGraph, 0, len(modifiedFuncs)),
		Warnings:          []string{},
		ImpactAnalysis: ImpactAnalysis{
			AffectedPackages: getAffectedPackages(modifiedFuncs),
		},
	}

	if len(modifiedFuncs) == 0 {
		return result, nil
	}

	// Truncate modified functions if exceeding limit
	if len(modifiedFuncs) > maxModifiedFunctions {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Truncated modified functions from %d to %d", len(modifiedFuncs), maxModifiedFunctions))
		modifiedFuncs = modifiedFuncs[:maxModifiedFunctions]
		result.PartialResults = true
	}

	// Apply default time budget if not specified
	if timeBudgetSec <= 0 {
		timeBudgetSec = defaultTimeBudgetSec
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeBudgetSec)*time.Second)
	defer cancel()

	// Determine patterns to load - use "./..." to load all packages in workspace
	patterns := []string{"./..."}

	// Load packages
	loadPackages := g.loadPackagesFn
	if loadPackages == nil {
		loadPackages = g.loadPackages
	}
	pkgs, pkgWarnings, err := loadPackages(ctx, patterns)
	if err != nil {
		// Check if context was cancelled (time budget exceeded)
		if ctx.Err() != nil {
			result.TimeBudgetExceeded = true
			result.PartialResults = true
			result.Warnings = append(result.Warnings, "Package loading timed out")
			return result, nil
		}
		return nil, fmt.Errorf("failed to load packages: %w", err)
	}

	// Merge package loading warnings
	result.Warnings = append(result.Warnings, pkgWarnings...)

	if len(pkgs) == 0 {
		result.Warnings = append(result.Warnings, "No packages found")
		return result, nil
	}

	// Build SSA
	prog := g.buildSSA(pkgs)
	if prog == nil {
		result.Warnings = append(result.Warnings, "SSA program build failed")
		result.PartialResults = true
		return result, nil
	}

	// Build call graph using CHA (Class Hierarchy Analysis)
	// CHA is fast but conservative - it over-approximates call targets
	cg := cha.CallGraph(prog)

	// Build a single index of SSA functions used by analyzeFunction and
	// findTransitiveCallers to avoid O(packages * members * methodSet) scans
	// on every lookup (see H19).
	ssaIndex := g.buildSSAIndex(prog)

	// Track all unique direct callers and affected tests
	allDirectCallers := make(map[string]bool)
	allAffectedTests := make(map[string]bool)

	// Count virtual edges so we can emit a single summary warning rather than
	// one per call site (see H15).
	virtualEdgeCount := 0

	// Analyze each modified function
	for _, modFunc := range modifiedFuncs {
		// Check for timeout
		select {
		case <-ctx.Done():
			result.TimeBudgetExceeded = true
			result.PartialResults = true
			result.Warnings = append(result.Warnings, "Analysis timed out during function processing")
			return result, nil
		default:
		}

		fcg, vCount := g.analyzeFunction(prog, cg, ssaIndex, modFunc, allDirectCallers, allAffectedTests)
		virtualEdgeCount += vCount
		result.ModifiedFunctions = append(result.ModifiedFunctions, fcg)
	}

	if virtualEdgeCount > 0 {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("CHA produced %d virtual (interface-dispatch) edges; these are over-approximations and may include infeasible targets", virtualEdgeCount))
	}

	// Calculate direct callers count
	result.ImpactAnalysis.DirectCallers = len(allDirectCallers)

	// Calculate transitive callers (excluding direct callers to avoid double-counting)
	transitiveCallers := g.findTransitiveCallers(cg, prog, ssaIndex, modifiedFuncs, 10)
	result.ImpactAnalysis.TransitiveCallers = len(transitiveCallers) - result.ImpactAnalysis.DirectCallers
	if result.ImpactAnalysis.TransitiveCallers < 0 {
		result.ImpactAnalysis.TransitiveCallers = 0
	}

	// Calculate affected tests count
	result.ImpactAnalysis.AffectedTests = len(allAffectedTests)

	return result, nil
}

// analyzeFunction analyzes a single function and returns its call graph.
// The second return value is the number of virtual (interface-dispatch) edges
// produced, used by the caller to emit a summary warning.
func (g *GoAnalyzer) analyzeFunction(
	prog *ssa.Program,
	cg *callgraph.Graph,
	ssaIndex map[string]*ssa.Function,
	modFunc ModifiedFunction,
	allDirectCallers map[string]bool,
	allAffectedTests map[string]bool,
) (FunctionCallGraph, int) {
	fcg := FunctionCallGraph{
		Function:     modFunc.Name,
		File:         modFunc.File,
		Callers:      make([]CallInfo, 0),
		Callees:      make([]CallInfo, 0),
		TestCoverage: make([]TestCoverage, 0),
	}

	// Find the SSA function via the prebuilt index.
	ssaFunc := lookupSSAFunction(ssaIndex, prog, modFunc, g.workDir)
	if ssaFunc == nil {
		return fcg, 0
	}

	// Get the call graph node for this function
	node := cg.Nodes[ssaFunc]
	if node == nil {
		return fcg, 0
	}

	virtualCount := 0

	// Find callers (incoming edges)
	for _, edge := range node.In {
		if edge.Caller == nil || edge.Caller.Func == nil {
			continue
		}

		callerFunc := edge.Caller.Func
		callerName := formatSSAFunctionName(callerFunc)

		// Get position of the call site
		var callSite string
		var line int
		var file string

		if edge.Site != nil && edge.Site.Pos().IsValid() {
			pos := prog.Fset.Position(edge.Site.Pos())
			file = pos.Filename
			line = pos.Line
			callSite = fmt.Sprintf("%s:%d", filepath.Base(pos.Filename), pos.Line)
		} else if callerFunc.Pos().IsValid() {
			pos := prog.Fset.Position(callerFunc.Pos())
			file = pos.Filename
			line = pos.Line
		}

		isVirtual := isVirtualEdge(edge)
		if isVirtual {
			virtualCount++
		}

		// Track unique callers
		callerKey := fmt.Sprintf("%s:%s", file, callerName)
		allDirectCallers[callerKey] = true

		// Check if caller is a test function
		if isTestFunction(callerName) {
			allAffectedTests[callerKey] = true
			fcg.TestCoverage = append(fcg.TestCoverage, TestCoverage{
				TestFunction: callerName,
				File:         file,
				Line:         line,
			})
		}

		fcg.Callers = append(fcg.Callers, CallInfo{
			Function:  callerName,
			File:      file,
			Line:      line,
			CallSite:  callSite,
			IsVirtual: isVirtual,
		})
	}

	// Find callees (outgoing edges)
	for _, edge := range node.Out {
		if edge.Callee == nil || edge.Callee.Func == nil {
			continue
		}

		calleeFunc := edge.Callee.Func
		calleeName := formatSSAFunctionName(calleeFunc)

		// Get position
		var file string
		var line int
		var callSite string

		if edge.Site != nil && edge.Site.Pos().IsValid() {
			pos := prog.Fset.Position(edge.Site.Pos())
			callSite = fmt.Sprintf("%s:%d", filepath.Base(pos.Filename), pos.Line)
		}

		if calleeFunc.Pos().IsValid() {
			pos := prog.Fset.Position(calleeFunc.Pos())
			file = pos.Filename
			line = pos.Line
		}

		isVirtual := isVirtualEdge(edge)
		if isVirtual {
			virtualCount++
		}

		fcg.Callees = append(fcg.Callees, CallInfo{
			Function:  calleeName,
			File:      file,
			Line:      line,
			CallSite:  callSite,
			IsVirtual: isVirtual,
		})
	}

	return fcg, virtualCount
}

// isVirtualEdge reports whether a call graph edge was produced by a dynamic
// (interface) dispatch. CHA conservatively materialises every type that
// satisfies the interface, so these edges are over-approximations rather than
// guaranteed call targets.
func isVirtualEdge(edge *callgraph.Edge) bool {
	if edge == nil || edge.Site == nil {
		return false
	}
	return edge.Site.Common().IsInvoke()
}

// buildSSAIndex enumerates all SSA functions (including methods) once and
// indexes them by file + qualified name so subsequent lookups are O(1) rather
// than the nested package/member/methodSet scan (see H19).
//
// Keys take two forms:
//   - "<file>|<Receiver>.<Name>" for methods
//   - "<file>|<Name>" for package-level functions
//
// Both pointer and value method sets are enumerated; both map to the same
// underlying SSA function and are deduped by the map.
func (g *GoAnalyzer) buildSSAIndex(prog *ssa.Program) map[string]*ssa.Function {
	index := make(map[string]*ssa.Function)
	if prog == nil {
		return index
	}

	addFn := func(fn *ssa.Function) {
		if fn == nil {
			return
		}
		name := fn.Name()
		var file string
		if fn.Pos().IsValid() {
			file = filepath.Clean(prog.Fset.Position(fn.Pos()).Filename)
		}
		qualified := name
		if recvType := safeReceiverTypeString(fn); recvType != "" {
			if idx := strings.LastIndex(recvType, "."); idx >= 0 {
				recvType = recvType[idx+1:]
			}
			recvType = strings.TrimPrefix(recvType, "*")
			qualified = recvType + "." + name
		}
		// Index by both (file, qualified) and (file, bare name) so callers
		// that do not know the receiver can still find the function.
		index[file+"|"+qualified] = fn
		if qualified != name {
			if _, ok := index[file+"|"+name]; !ok {
				index[file+"|"+name] = fn
			}
		}
	}

	for _, pkg := range prog.AllPackages() {
		if pkg == nil {
			continue
		}
		for _, member := range pkg.Members {
			switch m := member.(type) {
			case *ssa.Function:
				addFn(m)
			case *ssa.Type:
				mset := prog.MethodSets.MethodSet(m.Type())
				for i := 0; i < mset.Len(); i++ {
					addFn(prog.MethodValue(mset.At(i)))
				}
				pset := prog.MethodSets.MethodSet(types.NewPointer(m.Type()))
				for i := 0; i < pset.Len(); i++ {
					addFn(prog.MethodValue(pset.At(i)))
				}
			}
		}
	}

	return index
}

// lookupSSAFunction resolves a ModifiedFunction to its SSA representation using
// the prebuilt index. It falls back to a filename-suffix scan only when the
// exact (file, name) key is absent.
func lookupSSAFunction(index map[string]*ssa.Function, prog *ssa.Program, modFunc ModifiedFunction, workDir string) *ssa.Function {
	expectedName := modFunc.Name
	if modFunc.Receiver != "" {
		receiver := strings.TrimPrefix(modFunc.Receiver, "*")
		expectedName = receiver + "." + modFunc.Name
	}

	targetFile := filepath.Clean(modFunc.File)
	if !filepath.IsAbs(targetFile) && workDir != "" {
		targetFile = filepath.Clean(filepath.Join(workDir, modFunc.File))
	}

	if fn, ok := index[targetFile+"|"+expectedName]; ok {
		return fn
	}
	if fn, ok := index[targetFile+"|"+modFunc.Name]; ok {
		return fn
	}

	// Fallback: if the caller provided a non-absolute or non-matching path,
	// accept any indexed function whose file path ends with the target.
	base := filepath.Base(modFunc.File)
	for key, fn := range index {
		sep := strings.Index(key, "|")
		if sep < 0 {
			continue
		}
		file, name := key[:sep], key[sep+1:]
		if name != expectedName && name != modFunc.Name {
			continue
		}
		if strings.HasSuffix(file, modFunc.File) || filepath.Base(file) == base {
			return fn
		}
	}

	return nil
}

// isTestFunction checks if a function name indicates a test function.
func isTestFunction(name string) bool {
	// Remove receiver prefix if present
	if idx := strings.LastIndex(name, "."); idx >= 0 {
		name = name[idx+1:]
	}

	prefixes := []string{"Test", "Benchmark", "Example", "Fuzz"}
	for _, prefix := range prefixes {
		if !strings.HasPrefix(name, prefix) {
			continue
		}

		rest := strings.TrimPrefix(name, prefix)
		if rest == "" {
			return true
		}

		r, _ := utf8.DecodeRuneInString(rest)
		if !unicode.IsLower(r) {
			return true
		}
	}

	return false
}

// findTransitiveCallers performs BFS to find all transitive callers up to maxDepth.
func (g *GoAnalyzer) findTransitiveCallers(
	cg *callgraph.Graph,
	prog *ssa.Program,
	ssaIndex map[string]*ssa.Function,
	modifiedFuncs []ModifiedFunction,
	maxDepth int,
) map[string]bool {
	transitiveCallers := make(map[string]bool)

	// Start with all modified functions
	var startNodes []*callgraph.Node
	for _, modFunc := range modifiedFuncs {
		ssaFunc := lookupSSAFunction(ssaIndex, prog, modFunc, g.workDir)
		if ssaFunc == nil {
			continue
		}
		if node := cg.Nodes[ssaFunc]; node != nil {
			startNodes = append(startNodes, node)
		}
	}

	if len(startNodes) == 0 {
		return transitiveCallers
	}

	// BFS to find all transitive callers
	visited := make(map[*callgraph.Node]bool)
	queue := list.New()

	// Initialize queue with start nodes at depth 0
	for _, node := range startNodes {
		queue.PushBack(&nodeWithDepth{node: node, depth: 0})
		visited[node] = true
	}

	for queue.Len() > 0 {
		// Stop early if we've exceeded the transitive callers limit
		if len(transitiveCallers) >= maxTransitiveCallers {
			break
		}

		// Dequeue
		elem := queue.Front()
		current, ok := elem.Value.(*nodeWithDepth)
		if !ok || current == nil {
			queue.Remove(elem)
			continue
		}
		queue.Remove(elem)

		// Don't go beyond max depth
		if current.depth >= maxDepth {
			continue
		}

		// Process all callers (incoming edges)
		for _, edge := range current.node.In {
			if edge.Caller == nil || edge.Caller.Func == nil {
				continue
			}

			callerNode := edge.Caller
			if visited[callerNode] {
				continue
			}

			visited[callerNode] = true

			// Record this transitive caller
			callerFunc := callerNode.Func
			callerKey := callerFunc.String()
			if callerFunc.Pos().IsValid() {
				pos := prog.Fset.Position(callerFunc.Pos())
				callerKey = fmt.Sprintf("%s:%s", pos.Filename, formatSSAFunctionName(callerFunc))
			}
			transitiveCallers[callerKey] = true

			// Enqueue for further traversal
			queue.PushBack(&nodeWithDepth{
				node:  callerNode,
				depth: current.depth + 1,
			})
		}
	}

	return transitiveCallers
}

func formatSSAFunctionName(fn *ssa.Function) string {
	if fn == nil {
		return ""
	}

	name := fn.Name()
	if recvType := safeReceiverTypeString(fn); recvType != "" {
		name = recvType + "." + name
	}

	// Anonymous closures have SSA-synthesized names like "main$1" or
	// "funcN" that carry no meaning for reviewers. Qualify them with the
	// enclosing function so they are at least attributable.
	if parent := fn.Parent(); parent != nil {
		shortName := fn.Name()
		if isAnonymousSSAName(shortName) {
			parentName := parent.Name()
			if parentRecv := safeReceiverTypeString(parent); parentRecv != "" {
				parentName = parentRecv + "." + parentName
			}
			name = parentName + ".<closure:" + shortName + ">"
		}
	}

	return name
}

// isAnonymousSSAName reports whether an SSA function name looks auto-generated
// (e.g. "func1", "func12", or the "$N" suffix produced by the ssa package).
func isAnonymousSSAName(name string) bool {
	if name == "" {
		return true
	}
	if strings.HasPrefix(name, "func") {
		digits := name[len("func"):]
		if digits != "" {
			allDigits := true
			for _, r := range digits {
				if r < '0' || r > '9' {
					allDigits = false
					break
				}
			}
			if allDigits {
				return true
			}
		}
	}
	if idx := strings.LastIndex(name, "$"); idx >= 0 {
		tail := name[idx+1:]
		if tail != "" {
			allDigits := true
			for _, r := range tail {
				if r < '0' || r > '9' {
					allDigits = false
					break
				}
			}
			if allDigits {
				return true
			}
		}
	}
	return false
}

func safeReceiverTypeString(fn *ssa.Function) string {
	if fn == nil || fn.Signature == nil {
		return ""
	}
	recv := fn.Signature.Recv()
	if recv == nil || recv.Type() == nil {
		return ""
	}
	return recv.Type().String()
}

// nodeWithDepth is a helper struct for BFS traversal.
type nodeWithDepth struct {
	node  *callgraph.Node
	depth int
}
