package callgraph

// RiskLevel is a shared textual classification of call-graph impact
// based on direct caller count.
type RiskLevel string

const (
	// RiskHigh marks functions with a broad reach (>= HighImpactCallerThreshold callers).
	RiskHigh RiskLevel = "HIGH"
	// RiskMedium marks functions with some callers but below the high threshold.
	RiskMedium RiskLevel = "MEDIUM"
	// RiskLow marks functions with no callers in the graph.
	RiskLow RiskLevel = "LOW"
)

// HighImpactCallerThreshold is the minimum number of direct callers for
// a function to be classified as HIGH risk. Single source of truth shared
// by context/compiler builders, template rendering, and markdown output.
const HighImpactCallerThreshold = 3

// RiskLevelFromCallerCount returns the canonical risk level for a function
// with callerCount direct callers. Centralising this prevents drift between
// the markdown writer and the context template helpers.
func RiskLevelFromCallerCount(callerCount int) RiskLevel {
	switch {
	case callerCount >= HighImpactCallerThreshold:
		return RiskHigh
	case callerCount >= 1:
		return RiskMedium
	default:
		return RiskLow
	}
}
