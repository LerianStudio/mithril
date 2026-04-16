// Package scope handles reading and parsing scope.json from Phase 0.
package scope

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/lerianstudio/mithril/internal/callgraph"
	"github.com/lerianstudio/mithril/internal/fileutil"
	"github.com/lerianstudio/mithril/internal/lint"
)

// ScopeJSON represents the scope.json structure from Phase 0.
type ScopeJSON struct {
	BaseRef   string        `json:"base_ref"`
	HeadRef   string        `json:"head_ref"`
	Language  string        `json:"language"` // Primary detected language
	Languages []string      `json:"languages,omitempty"`
	Files     FilesByStatus `json:"files"`
	Stats     StatsJSON     `json:"stats"`
	Packages  []string      `json:"packages_affected"`
}

func normalizeScopeJSON(scope *ScopeJSON) {
	if scope == nil {
		return
	}
	if scope.Files.Modified == nil {
		scope.Files.Modified = []string{}
	}
	if scope.Files.Added == nil {
		scope.Files.Added = []string{}
	}
	if scope.Files.Deleted == nil {
		scope.Files.Deleted = []string{}
	}
	if scope.Files.Renamed == nil {
		scope.Files.Renamed = []RenamedFile{}
	}
	if scope.Languages == nil {
		scope.Languages = []string{}
	}
	if scope.Packages == nil {
		scope.Packages = []string{}
	}
}

// FilesByStatus holds categorized file lists.
//
// Modified, Added, and Deleted are mutually exclusive by path. Renamed is a
// supplementary list of {old -> new} pairs; when populated, the new path is
// also present in Added (or Modified for copy/rename-with-edit semantics),
// preserving backward-compat for consumers that ignore Renamed.
type FilesByStatus struct {
	Modified []string      `json:"modified"`
	Added    []string      `json:"added"`
	Deleted  []string      `json:"deleted"`
	Renamed  []RenamedFile `json:"renamed,omitempty"`
}

// RenamedFile captures a rename/copy operation so downstream consumers can
// track identity across moves instead of treating it as delete+add.
type RenamedFile struct {
	OldPath string `json:"old_path"`
	NewPath string `json:"new_path"`
}

// StatsJSON holds change statistics.
type StatsJSON struct {
	TotalFiles     int `json:"total_files"`
	TotalAdditions int `json:"total_additions"`
	TotalDeletions int `json:"total_deletions"`
}

// ReadScopeJSON reads and parses scope.json from the given path.
func ReadScopeJSON(scopePath string) (*ScopeJSON, error) {
	data, err := fileutil.ReadJSONFileWithLimit(scopePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read scope.json: %w", err)
	}

	var scope ScopeJSON
	if err := json.Unmarshal(data, &scope); err != nil {
		return nil, fmt.Errorf("failed to parse scope.json: %w", err)
	}

	normalizeScopeJSON(&scope)
	return &scope, nil
}

// GetLanguage returns the primary language as a lint.Language.
func (s *ScopeJSON) GetLanguage() lint.Language {
	if s == nil {
		return lint.Language("")
	}

	switch s.Language {
	case "go":
		return lint.LanguageGo
	case "typescript", "ts":
		return lint.LanguageTypeScript
	case "python", "py":
		return lint.LanguagePython
	case "mixed":
		return lint.LanguageMixed

	default:
		return lint.Language("")
	}
}

// GetAnalyzableFiles returns the changed files that still exist on disk and
// can be fed to linters, AST extractors, and dataflow analyzers (Modified +
// Added). Deleted files are intentionally excluded because they have no
// current content to analyze; use GetAllChangedFiles or GetDeletedFiles for
// deletion-aware workflows.
func (s *ScopeJSON) GetAnalyzableFiles() []string {
	if s == nil {
		return []string{}
	}

	all := make([]string, 0, len(s.Files.Modified)+len(s.Files.Added))
	for _, f := range s.Files.Modified {
		all = append(all, normalizeScopePath(f))
	}
	for _, f := range s.Files.Added {
		all = append(all, normalizeScopePath(f))
	}
	return all
}

// GetAllChangedFiles returns every path touched by the change (Modified +
// Added + Deleted + old paths of Renamed entries). Use this when you need to
// reason about deletion-based regressions (e.g. an attacker removing an auth
// check) — the deleted paths let callers fetch the "before" version from git
// and diff against nothing.
func (s *ScopeJSON) GetAllChangedFiles() []string {
	if s == nil {
		return []string{}
	}

	seen := make(map[string]struct{})
	all := make([]string, 0, len(s.Files.Modified)+len(s.Files.Added)+len(s.Files.Deleted)+len(s.Files.Renamed))
	add := func(raw string) {
		if raw == "" {
			return
		}
		p := normalizeScopePath(raw)
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		all = append(all, p)
	}
	for _, f := range s.Files.Modified {
		add(f)
	}
	for _, f := range s.Files.Added {
		add(f)
	}
	for _, f := range s.Files.Deleted {
		add(f)
	}
	for _, r := range s.Files.Renamed {
		add(r.OldPath)
		add(r.NewPath)
	}
	return all
}

// GetDeletedFiles returns the normalized paths of files removed by the change.
// Callers wanting to analyze the removed content should load it via
// `git show <base-ref>:<path>` rather than the working tree.
func (s *ScopeJSON) GetDeletedFiles() []string {
	if s == nil {
		return []string{}
	}
	deleted := make([]string, 0, len(s.Files.Deleted))
	for _, f := range s.Files.Deleted {
		deleted = append(deleted, normalizeScopePath(f))
	}
	return deleted
}

// GetAnalyzableFilesMap returns a set of analyzable file paths for quick
// lookups. Mirrors GetAnalyzableFiles semantics (Modified + Added).
func (s *ScopeJSON) GetAnalyzableFilesMap() map[string]bool {
	if s == nil {
		return map[string]bool{}
	}

	fileMap := make(map[string]bool)
	for _, f := range s.Files.Modified {
		fileMap[normalizeScopePath(f)] = true
	}
	for _, f := range s.Files.Added {
		fileMap[normalizeScopePath(f)] = true
	}
	return fileMap
}

// NormalizeLanguage maps supported language aliases to canonical identifiers.
func NormalizeLanguage(lang string) lint.Language {
	if strings.EqualFold(strings.TrimSpace(lang), "mixed") {
		return lint.LanguageMixed
	}
	normalized := callgraph.NormalizeLanguage(lang)
	if normalized == "" {
		return lint.Language("")
	}
	return lint.Language(normalized)
}

// normalizeScopePath normalizes file paths for consistent matching.
// Strips leading "./" or ".\\" and cleans path separators.
func normalizeScopePath(path string) string {
	path = filepath.Clean(path)
	path = strings.TrimPrefix(path, "./")
	path = strings.TrimPrefix(path, ".\\")
	return path
}

// GetPackages returns the affected packages.
func (s *ScopeJSON) GetPackages() []string {
	if s == nil {
		return []string{}
	}

	return s.Packages
}

// DefaultScopePath returns the default scope.json path.
func DefaultScopePath(projectDir string) string {
	return filepath.Join(projectDir, ".ring", "codereview", "scope.json")
}
