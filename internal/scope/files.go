package scope

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// ExpandFilePatterns expands glob patterns into a list of repo-relative file paths.
// Supports ** for matching multiple path segments.
func ExpandFilePatterns(workDir string, patterns []string) ([]string, error) {
	if len(patterns) == 0 {
		return nil, fmt.Errorf("no file patterns provided")
	}

	baseDir := workDir
	if baseDir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to resolve working directory: %w", err)
		}
		baseDir = cwd
	}

	matches := make(map[string]bool)
	globPatterns := make([]string, 0, len(patterns))
	for _, raw := range patterns {
		pattern := strings.TrimSpace(raw)
		if pattern == "" {
			continue
		}

		if err := validatePattern(pattern); err != nil {
			return nil, err
		}

		if hasGlob(pattern) {
			globPatterns = append(globPatterns, pattern)
			continue
		}

		cleaned := normalizePath(pattern)
		matches[cleaned] = true
	}

	if len(globPatterns) > 0 {
		found, err := expandGlobPatterns(baseDir, globPatterns)
		if err != nil {
			return nil, err
		}
		for _, match := range found {
			matches[match] = true
		}
	}

	if len(matches) == 0 {
		return []string{}, nil
	}

	result := make([]string, 0, len(matches))
	for file := range matches {
		cleaned := normalizePath(file)
		if cleaned != "" {
			result = append(result, cleaned)
		}
	}
	sort.Strings(result)
	return result, nil
}

func expandGlobPatterns(baseDir string, patterns []string) ([]string, error) {
	normalizedPatterns := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		normalizedPattern := path.Clean(filepath.ToSlash(pattern))
		if strings.HasPrefix(normalizedPattern, "../") || normalizedPattern == ".." {
			return nil, fmt.Errorf("pattern contains path traversal: %s", pattern)
		}
		normalizedPatterns = append(normalizedPatterns, normalizedPattern)
	}

	results := make(map[string]bool)
	err := filepath.WalkDir(baseDir, func(fullPath string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules", "vendor":
				return filepath.SkipDir
			default:
				return nil
			}
		}

		rel, err := filepath.Rel(baseDir, fullPath)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)

		for _, pattern := range normalizedPatterns {
			matched, matchErr := matchGlob(pattern, rel)
			if matchErr != nil {
				return matchErr
			}
			if matched {
				results[normalizePath(rel)] = true
				break
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	out := make([]string, 0, len(results))
	for result := range results {
		out = append(out, result)
	}

	return out, nil
}

func validatePattern(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("pattern cannot be empty")
	}
	if strings.ContainsRune(pattern, '\x00') {
		return fmt.Errorf("pattern contains null byte")
	}
	if filepath.IsAbs(pattern) {
		return fmt.Errorf("pattern must be relative: %s", pattern)
	}
	cleaned := filepath.Clean(pattern)
	if cleaned == "." {
		return fmt.Errorf("pattern must not be current directory")
	}

	normalized := strings.ReplaceAll(cleaned, "\\", "/")
	for _, segment := range strings.Split(normalized, "/") {
		if segment == ".." {
			return fmt.Errorf("pattern contains path traversal: %s", pattern)
		}
	}
	return nil
}

func normalizePath(value string) string {
	cleaned := filepath.Clean(value)
	cleaned = strings.TrimPrefix(cleaned, "./")
	cleaned = strings.TrimPrefix(cleaned, ".\\")
	return cleaned
}

func hasGlob(pattern string) bool {
	return strings.ContainsAny(pattern, "*?[")
}

func matchGlob(pattern, target string) (bool, error) {
	pattern = path.Clean(pattern)
	target = path.Clean(target)

	patternSegments := strings.Split(pattern, "/")
	targetSegments := strings.Split(target, "/")

	cache := make(map[string]bool)
	return matchGlobSegments(patternSegments, targetSegments, cache)
}

func matchGlobSegments(patternSegments, targetSegments []string, cache map[string]bool) (bool, error) {
	cacheKey := fmt.Sprintf("%d:%d:%s:%s", len(patternSegments), len(targetSegments), strings.Join(patternSegments, "/"), strings.Join(targetSegments, "/"))
	if cached, ok := cache[cacheKey]; ok {
		return cached, nil
	}

	if len(patternSegments) == 0 {
		matched := len(targetSegments) == 0
		cache[cacheKey] = matched
		return matched, nil
	}

	segment := patternSegments[0]
	if segment == "**" {
		if len(patternSegments) == 1 {
			cache[cacheKey] = true
			return true, nil
		}
		for i := 0; i <= len(targetSegments); i++ {
			matched, err := matchGlobSegments(patternSegments[1:], targetSegments[i:], cache)
			if err != nil {
				return false, err
			}
			if matched {
				cache[cacheKey] = true
				return true, nil
			}
		}
		cache[cacheKey] = false
		return false, nil
	}

	if len(targetSegments) == 0 {
		cache[cacheKey] = false
		return false, nil
	}

	ok, err := path.Match(segment, targetSegments[0])
	if err != nil {
		return false, fmt.Errorf("invalid glob pattern %q: %w", segment, err)
	}
	if !ok {
		cache[cacheKey] = false
		return false, nil
	}

	matched, err := matchGlobSegments(patternSegments[1:], targetSegments[1:], cache)
	if err != nil {
		return false, err
	}
	cache[cacheKey] = matched
	return matched, nil
}
