package lint

import (
	"context"
	"fmt"
)

// recordToolVersion collects version info for a tool. If the version lookup
// fails, an error entry is appended to result and false is returned.
func recordToolVersion(ctx context.Context, result *Result, tool string, fn func(ctx context.Context) (string, error)) bool {
	version, err := fn(ctx)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("%s version check failed: %v", tool, err))
		return false
	}
	result.ToolVersions[tool] = version
	return true
}

// appendValidationError validates targets and, on failure, appends a formatted
// error to the result. Returns true if targets are valid.
func appendValidationError(result *Result, tool string, targets []string) bool {
	if err := validateTargetArgs(targets); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("%s target validation failed: %v", tool, err))
		return false
	}
	return true
}

// appendExecError formats a linter execution error in the canonical shape.
func appendExecError(result *Result, tool string, err error) {
	result.Errors = append(result.Errors, fmt.Sprintf("%s execution failed: %v", tool, err))
}

// appendParseError formats a JSON/output parse warning.
func appendParseError(result *Result, tool string, err error) {
	result.Errors = append(result.Errors, fmt.Sprintf("%s output parse warning: %v", tool, err))
}
