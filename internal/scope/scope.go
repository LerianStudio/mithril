// Package scope provides language detection and file categorization for code review.
package scope

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/lerianstudio/mithril/internal/git"
)

// Language represents the programming language of code files.
type Language int

const (
	LanguageUnknown Language = iota
	LanguageGo
	LanguageTypeScript
	LanguagePython
	LanguageMixed
)

// String returns the string representation of the language.
func (l Language) String() string {
	switch l {
	case LanguageGo:
		return "go"
	case LanguageTypeScript:
		return "typescript"
	case LanguagePython:
		return "python"
	case LanguageMixed:
		return "mixed"
	default:
		return "unknown"
	}
}

// extensionToLanguage maps file extensions to their respective languages.
var extensionToLanguage = map[string]Language{
	".go":  LanguageGo,
	".ts":  LanguageTypeScript,
	".tsx": LanguageTypeScript,
	".py":  LanguagePython,
}

// ScopeResult contains the analysis of changed files.
type ScopeResult struct {
	BaseRef          string
	HeadRef          string
	Language         string
	Languages        []string
	ModifiedFiles    []string
	AddedFiles       []string
	DeletedFiles     []string
	RenamedFiles     []RenamedFile
	TotalFiles       int
	TotalAdditions   int
	TotalDeletions   int
	PackagesAffected []string
}

// gitClientInterface defines the git operations needed by Detector.
type gitClientInterface interface {
	GetDiff(baseRef, headRef string) (*git.DiffResult, error)
	GetAllChangesDiff() (*git.DiffResult, error)
	GetStagedDiff() (*git.DiffResult, error)
	GetDiffStatsForFiles(baseRef string, files []string) (git.DiffStats, map[string]git.FileStats, error)
	FileExistsAtRef(ref, path string) (bool, error)
	ListUnstagedFiles() ([]string, error)
}

// Detector analyzes git diffs to determine language and file categorization.
type Detector struct {
	workDir   string
	gitClient gitClientInterface
	// logf is an optional structured log sink invoked when the detector
	// needs to report a skipped file (for example, a race between listing
	// and stat-ing a path). Callers that want operator visibility should set
	// this; nil means "silently drop the message".
	logf func(format string, args ...any)
}

// NewDetector creates a new Detector for the specified working directory.
func NewDetector(workDir string) *Detector {
	return &Detector{
		workDir:   workDir,
		gitClient: git.NewClient(workDir),
	}
}

// SetLogger installs a logging function that the Detector calls with a
// Printf-style message whenever it gracefully skips a file. Passing nil
// disables logging.
func (d *Detector) SetLogger(logf func(format string, args ...any)) {
	if d == nil {
		return
	}
	d.logf = logf
}

func (d *Detector) logSkip(format string, args ...any) {
	if d == nil || d.logf == nil {
		return
	}
	d.logf(format, args...)
}

// DetectFromRefs analyzes changes between two git refs.
func (d *Detector) DetectFromRefs(baseRef, headRef string) (*ScopeResult, error) {
	diffResult, err := d.gitClient.GetDiff(baseRef, headRef)
	if err != nil {
		return nil, err
	}

	return d.buildScopeResult(diffResult)
}

// DetectAllChanges analyzes all staged and unstaged changes.
func (d *Detector) DetectAllChanges() (*ScopeResult, error) {
	diffResult, err := d.gitClient.GetAllChangesDiff()
	if err != nil {
		return nil, err
	}

	return d.buildScopeResult(diffResult)
}

// DetectStagedChanges analyzes only staged changes (index vs HEAD).
func (d *Detector) DetectStagedChanges() (*ScopeResult, error) {
	diffResult, err := d.gitClient.GetStagedDiff()
	if err != nil {
		return nil, err
	}

	return d.buildScopeResult(diffResult)
}

// DetectUnstagedChanges analyzes only unstaged and untracked files.
func (d *Detector) DetectUnstagedChanges() (*ScopeResult, error) {
	files, err := d.gitClient.ListUnstagedFiles()
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return d.emptyScopeResult("HEAD", "working-tree"), nil
	}
	return d.buildScopeResultFromFiles("HEAD", files)
}

// buildScopeResultFromFiles analyzes a list of files against a base ref.
func (d *Detector) buildScopeResultFromFiles(baseRef string, files []string) (*ScopeResult, error) {
	cleanFiles := normalizeFileList(files)
	if len(cleanFiles) == 0 {
		return d.emptyScopeResult(baseRef, "working-tree"), nil
	}

	stats, statsByFile, err := d.gitClient.GetDiffStatsForFiles(baseRef, cleanFiles)
	if err != nil {
		return nil, fmt.Errorf("failed to get diff stats for files: %w", err)
	}

	changedFiles := make([]git.ChangedFile, 0, len(cleanFiles))
	survivors := make([]string, 0, len(cleanFiles))
	for _, file := range cleanFiles {
		status, statusErr := resolveFileStatus(d.gitClient, d.workDir, baseRef, file)
		if statusErr != nil {
			// Races (file listed but vanished before stat) are operationally
			// normal — IDE saves, git ops, concurrent refactors. Skip the
			// file with a visible log instead of failing the whole scope.
			if errors.Is(statusErr, errFileRaceMissing) {
				d.logSkip("scope: skipping %q (disappeared between list and stat: %v)", file, statusErr)
				continue
			}
			return nil, statusErr
		}
		if status == git.StatusUnknown {
			status = git.StatusModified
		}

		// Ensure statsByFile is not nil and handles missing entries gracefully
		var fileStats git.FileStats
		if statsByFile != nil {
			fileStats = findFileStats(statsByFile, file)
		}

		changedFiles = append(changedFiles, git.ChangedFile{
			Path:      file,
			Status:    status,
			Additions: fileStats.Additions,
			Deletions: fileStats.Deletions,
		})
		survivors = append(survivors, file)
	}
	cleanFiles = survivors

	lang := DetectLanguage(cleanFiles)
	languages := DetectLanguages(cleanFiles)
	packages := ExtractPackages(FilterByLanguage(cleanFiles, lang))
	modified, added, deleted, renamed := CategorizeFilesByStatusWithRenames(changedFiles)

	return &ScopeResult{
		BaseRef:          baseRef,
		HeadRef:          "working-tree",
		Language:         lang.String(),
		Languages:        languages,
		ModifiedFiles:    modified,
		AddedFiles:       added,
		DeletedFiles:     deleted,
		RenamedFiles:     renamed,
		TotalFiles:       len(cleanFiles),
		TotalAdditions:   stats.TotalAdditions,
		TotalDeletions:   stats.TotalDeletions,
		PackagesAffected: packages,
	}, nil
}

func (d *Detector) emptyScopeResult(baseRef, headRef string) *ScopeResult {
	return &ScopeResult{
		BaseRef:          baseRef,
		HeadRef:          headRef,
		Language:         LanguageUnknown.String(),
		Languages:        []string{},
		ModifiedFiles:    []string{},
		AddedFiles:       []string{},
		DeletedFiles:     []string{},
		RenamedFiles:     []RenamedFile{},
		TotalFiles:       0,
		TotalAdditions:   0,
		TotalDeletions:   0,
		PackagesAffected: []string{},
	}
}

// buildScopeResult creates a ScopeResult from a git DiffResult.
func (d *Detector) buildScopeResult(diffResult *git.DiffResult) (*ScopeResult, error) {
	if diffResult == nil {
		return nil, fmt.Errorf("diff result cannot be nil")
	}

	// Extract all file paths
	var allPaths []string
	for _, f := range diffResult.Files {
		allPaths = append(allPaths, f.Path)
	}

	// Detect language
	lang := DetectLanguage(allPaths)

	// Categorize files by status
	modified, added, deleted, renamed := CategorizeFilesByStatusWithRenames(diffResult.Files)

	// Extract packages from code files only
	codeFiles := FilterByLanguage(allPaths, lang)
	packages := ExtractPackages(codeFiles)

	languages := DetectLanguages(allPaths)

	return &ScopeResult{
		BaseRef:          diffResult.BaseRef,
		HeadRef:          diffResult.HeadRef,
		Language:         lang.String(),
		Languages:        languages,
		ModifiedFiles:    modified,
		AddedFiles:       added,
		DeletedFiles:     deleted,
		RenamedFiles:     renamed,
		TotalFiles:       diffResult.Stats.TotalFiles,
		TotalAdditions:   diffResult.Stats.TotalAdditions,
		TotalDeletions:   diffResult.Stats.TotalDeletions,
		PackagesAffected: packages,
	}, nil
}

// DetectLanguage detects the primary programming language from a list of file paths.
// Returns LanguageMixed if multiple code languages are detected.
func DetectLanguage(files []string) Language {
	languagesFound := make(map[Language]bool)

	for _, f := range files {
		ext := strings.ToLower(getFileExtension(f))
		if lang, ok := extensionToLanguage[ext]; ok {
			languagesFound[lang] = true
		}
	}

	// Count detected code languages (not LanguageUnknown)
	count := len(languagesFound)

	if count == 0 {
		return LanguageUnknown
	}

	if count > 1 {
		return LanguageMixed
	}

	// Return the single detected language (count == 1 guarantees exactly one iteration)
	for lang := range languagesFound {
		return lang
	}
	return LanguageUnknown // Required by compiler; logically unreachable
}

// DetectLanguages returns all detected programming languages from a list of file paths.
// Results are returned as normalized language strings.
func DetectLanguages(files []string) []string {
	if len(files) == 0 {
		return []string{}
	}

	languagesFound := make(map[Language]bool)
	for _, f := range files {
		ext := strings.ToLower(getFileExtension(f))
		if lang, ok := extensionToLanguage[ext]; ok {
			languagesFound[lang] = true
		}
	}

	if len(languagesFound) == 0 {
		return []string{}
	}

	languages := make([]string, 0, len(languagesFound))
	for lang := range languagesFound {
		languages = append(languages, lang.String())
	}
	sort.Strings(languages)
	return languages
}

// getFileExtension returns the file extension including the dot.
// Returns empty string for files without extensions or hidden files.
func getFileExtension(path string) string {
	if path == "" {
		return ""
	}

	// Get the base name (last component of path)
	base := filepath.Base(path)

	// Handle hidden files (start with dot but no other extension)
	if strings.HasPrefix(base, ".") && !strings.Contains(base[1:], ".") {
		return ""
	}

	ext := filepath.Ext(base)
	return ext
}

// CategorizeFilesByStatus separates files into modified, added, and deleted
// categories. Renamed and copied files are treated as modified so the new
// path is still exercised by downstream analysis. The rename/copy link is
// intentionally lost here; callers that need identity-preservation across
// moves should use CategorizeFilesByStatusWithRenames instead.
func CategorizeFilesByStatus(files []git.ChangedFile) (modified, added, deleted []string) {
	modified, added, deleted, _ = CategorizeFilesByStatusWithRenames(files)
	return modified, added, deleted
}

// CategorizeFilesByStatusWithRenames separates files into modified, added,
// deleted, and renamed categories while preserving the OldPath→NewPath link
// for renames/copies. Renamed/copied entries also appear in `modified` so
// linters and dataflow still run on the new path (backward-compatible with
// callers that ignore the rename list).
func CategorizeFilesByStatusWithRenames(files []git.ChangedFile) (modified, added, deleted []string, renamed []RenamedFile) {
	modified = make([]string, 0)
	added = make([]string, 0)
	deleted = make([]string, 0)
	renamed = make([]RenamedFile, 0)

	for _, f := range files {
		switch f.Status {
		case git.StatusAdded:
			added = append(added, f.Path)
		case git.StatusDeleted:
			deleted = append(deleted, f.Path)
		case git.StatusRenamed, git.StatusCopied:
			modified = append(modified, f.Path)
			if f.OldPath != "" && f.OldPath != f.Path {
				renamed = append(renamed, RenamedFile{OldPath: f.OldPath, NewPath: f.Path})
			}
		default:
			// StatusModified, StatusUnknown -> modified
			modified = append(modified, f.Path)
		}
	}

	return modified, added, deleted, renamed
}

// ExtractPackages returns unique parent directories (packages) from file paths.
// Results are sorted alphabetically.
func ExtractPackages(files []string) []string {
	if len(files) == 0 {
		return []string{}
	}

	packageSet := make(map[string]bool)

	for _, f := range files {
		dir := filepath.Dir(f)
		if dir == "" || dir == "." {
			dir = "."
		}
		packageSet[dir] = true
	}

	// Convert set to slice
	packages := make([]string, 0, len(packageSet))
	for pkg := range packageSet {
		packages = append(packages, pkg)
	}

	// Sort for consistent output
	sort.Strings(packages)

	return packages
}

// FilterByLanguage returns only files matching the specified language.
// If language is LanguageUnknown, returns all files.
func FilterByLanguage(files []string, lang Language) []string {
	if len(files) == 0 {
		return []string{}
	}

	// For unknown or mixed language, return all files
	if lang == LanguageUnknown || lang == LanguageMixed {
		result := make([]string, len(files))
		copy(result, files)
		return result
	}

	result := make([]string, 0)

	for _, f := range files {
		ext := strings.ToLower(getFileExtension(f))
		if fileLang, ok := extensionToLanguage[ext]; ok && fileLang == lang {
			result = append(result, f)
		}
	}

	return result
}
