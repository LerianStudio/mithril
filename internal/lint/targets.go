package lint

import (
	"fmt"
	"strings"

	"github.com/lerianstudio/mithril/internal/fileutil"
)

// validateTargetArgs validates command targets from scope data before passing
// them to external linters.
func validateTargetArgs(targets []string) error {
	for _, target := range targets {
		trimmed := strings.TrimSpace(target)
		if trimmed == "" {
			return fmt.Errorf("target cannot be empty")
		}
		if strings.HasPrefix(trimmed, "-") {
			return fmt.Errorf("invalid target (starts with dash): %s", target)
		}
		if _, err := fileutil.ValidateRelativePath(trimmed); err != nil {
			return fmt.Errorf("invalid target path %q: %w", target, err)
		}
	}

	return nil
}
