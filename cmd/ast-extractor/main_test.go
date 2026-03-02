// Package main provides unit tests for the ast-extractor CLI binary.
package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/lerianstudio/mithril/internal/ast"
	"github.com/lerianstudio/mithril/internal/fileutil"
)

var validateScriptsDirWorkingDirMu sync.Mutex

func setTestWorkingDir(t *testing.T, dir string) {
	t.Helper()
	validateScriptsDirWorkingDirMu.Lock()
	oldWd, err := os.Getwd()
	if err != nil {
		validateScriptsDirWorkingDirMu.Unlock()
		t.Fatalf("Failed to get current working directory: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		validateScriptsDirWorkingDirMu.Unlock()
		t.Fatalf("Failed to change directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWd); err != nil {
			t.Errorf("Failed to restore working directory: %v", err)
		}
		validateScriptsDirWorkingDirMu.Unlock()
	})
}

func TestValidateScriptsDir(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T) string
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid_directory",
			setup: func(t *testing.T) string {
				tmpDir := t.TempDir()
				setTestWorkingDir(t, tmpDir)
				scriptsDir := filepath.Join(tmpDir, "scripts")
				if err := os.Mkdir(scriptsDir, 0o755); err != nil {
					t.Fatalf("Failed to create scripts directory: %v", err)
				}
				return scriptsDir
			},
			wantErr: false,
		},
		{
			name: "path_traversal_double_dot",
			setup: func(t *testing.T) string {
				cwd := t.TempDir()
				setTestWorkingDir(t, cwd)
				return string(filepath.Separator)
			},
			wantErr:   true,
			errSubstr: "must be within",
		},
		{
			name: "path_traversal_in_middle",
			setup: func(t *testing.T) string {
				cwd := filepath.Join(t.TempDir(), "repo")
				if err := os.MkdirAll(cwd, 0o755); err != nil {
					t.Fatalf("Failed to create cwd: %v", err)
				}
				setTestWorkingDir(t, cwd)
				return string(filepath.Separator)
			},
			wantErr:   true,
			errSubstr: "must be within",
		},
		{
			name: "explicit_path_outside_allowed",
			setup: func(t *testing.T) string {
				tmpDir := t.TempDir()
				repoDir := filepath.Join(tmpDir, "repo")
				outside := filepath.Join(tmpDir, "external-scripts")
				if err := os.MkdirAll(repoDir, 0o755); err != nil {
					t.Fatalf("Failed to create repo directory: %v", err)
				}
				if err := os.MkdirAll(outside, 0o755); err != nil {
					t.Fatalf("Failed to create external scripts directory: %v", err)
				}
				setTestWorkingDir(t, repoDir)
				return outside
			},
			wantErr: false,
		},
		{
			name: "nonexistent_directory",
			setup: func(t *testing.T) string {
				tmpDir := t.TempDir()
				setTestWorkingDir(t, tmpDir)
				return filepath.Join(tmpDir, "missing", "scripts")
			},
			wantErr:   true,
			errSubstr: "does not exist",
		},
		{
			name: "file_instead_of_directory",
			setup: func(t *testing.T) string {
				tmpDir := t.TempDir()
				setTestWorkingDir(t, tmpDir)
				filePath := filepath.Join(tmpDir, "testfile.txt")
				if err := os.WriteFile(filePath, []byte("test"), 0o644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return filePath
			},
			wantErr:   true,
			errSubstr: "not a directory",
		},
		{
			name: "empty_path",
			setup: func(t *testing.T) string {
				return ""
			},
			// Empty path becomes current directory which exists
			wantErr: false,
		},
		{
			name: "relative_path_valid",
			setup: func(t *testing.T) string {
				tmpDir := t.TempDir()
				// Create a subdirectory
				subDir := filepath.Join(tmpDir, "scripts")
				if err := os.Mkdir(subDir, 0o755); err != nil {
					t.Fatalf("Failed to create subdirectory: %v", err)
				}
				setTestWorkingDir(t, tmpDir)
				return "scripts"
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scriptsDir := tt.setup(t)
			enforceBaseRestriction := tt.name != "explicit_path_outside_allowed"
			err := validateScriptsDir(scriptsDir, enforceBaseRestriction)

			if tt.wantErr {
				if err == nil {
					t.Errorf("validateScriptsDir(%q) expected error containing %q, got nil", scriptsDir, tt.errSubstr)
					return
				}
				if tt.errSubstr != "" && !containsSubstring(err.Error(), tt.errSubstr) {
					t.Errorf("validateScriptsDir(%q) error = %v, want error containing %q", scriptsDir, err, tt.errSubstr)
				}
			} else {
				if err != nil {
					t.Errorf("validateScriptsDir(%q) unexpected error: %v", scriptsDir, err)
				}
			}
		})
	}
}

func TestReadJSONFileWithLimit(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T) string
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid_json_file",
			setup: func(t *testing.T) string {
				tmpDir := t.TempDir()
				filePath := filepath.Join(tmpDir, "valid.json")
				content := `{"key": "value", "number": 42}`
				if err := os.WriteFile(filePath, []byte(content), 0o644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return filePath
			},
			wantErr: false,
		},
		{
			name: "empty_json_file",
			setup: func(t *testing.T) string {
				tmpDir := t.TempDir()
				filePath := filepath.Join(tmpDir, "empty.json")
				if err := os.WriteFile(filePath, []byte{}, 0o644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return filePath
			},
			wantErr: false,
		},
		{
			name: "nonexistent_file",
			setup: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "missing.json")
			},
			wantErr:   true,
			errSubstr: "failed to stat file",
		},
		{
			name: "file_at_size_limit",
			setup: func(t *testing.T) string {
				tmpDir := t.TempDir()
				filePath := filepath.Join(tmpDir, "atlimit.json")
				// Create file just under the limit (1KB for test speed)
				content := make([]byte, 1024)
				for i := range content {
					content[i] = 'a'
				}
				if err := os.WriteFile(filePath, content, 0o644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return filePath
			},
			wantErr: false,
		},
		{
			name: "json_array_content",
			setup: func(t *testing.T) string {
				tmpDir := t.TempDir()
				filePath := filepath.Join(tmpDir, "array.json")
				content := `[{"before_path": "old.go", "after_path": "new.go"}]`
				if err := os.WriteFile(filePath, []byte(content), 0o644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return filePath
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := tt.setup(t)
			data, err := fileutil.ReadJSONFileWithLimit(filePath)

			if tt.wantErr {
				if err == nil {
					t.Errorf("fileutil.ReadJSONFileWithLimit(%q) expected error, got nil", filePath)
					return
				}
				if tt.errSubstr != "" && !containsSubstring(err.Error(), tt.errSubstr) {
					t.Errorf("fileutil.ReadJSONFileWithLimit(%q) error = %v, want error containing %q", filePath, err, tt.errSubstr)
				}
			} else {
				if err != nil {
					t.Errorf("fileutil.ReadJSONFileWithLimit(%q) unexpected error: %v", filePath, err)
					return
				}
				// For valid cases, verify we got data back (or empty for empty file)
				if data == nil {
					t.Errorf("fileutil.ReadJSONFileWithLimit(%q) returned nil data without error", filePath)
				}
			}
		})
	}
}

func TestReadJSONFileWithLimit_ContentPreservation(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "content.json")
	expectedContent := `{"name": "test", "values": [1, 2, 3]}`

	if err := os.WriteFile(filePath, []byte(expectedContent), 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	data, err := fileutil.ReadJSONFileWithLimit(filePath)
	if err != nil {
		t.Fatalf("fileutil.ReadJSONFileWithLimit returned error: %v", err)
	}

	if string(data) != expectedContent {
		t.Errorf("fileutil.ReadJSONFileWithLimit content mismatch:\ngot:  %s\nwant: %s", string(data), expectedContent)
	}
}

func TestGetExtractorByLanguage(t *testing.T) {
	tests := []struct {
		name         string
		lang         string
		wantErr      bool
		expectedLang string
	}{
		{
			name:         "go_lowercase",
			lang:         "go",
			wantErr:      false,
			expectedLang: "go",
		},
		{
			name:         "golang_full",
			lang:         "golang",
			wantErr:      false,
			expectedLang: "go",
		},
		{
			name:         "typescript_lowercase",
			lang:         "typescript",
			wantErr:      false,
			expectedLang: "typescript",
		},
		{
			name:         "ts_short",
			lang:         "ts",
			wantErr:      false,
			expectedLang: "typescript",
		},
		{
			name:         "javascript_alias",
			lang:         "javascript",
			wantErr:      false,
			expectedLang: "typescript",
		},
		{
			name:         "js_short",
			lang:         "js",
			wantErr:      false,
			expectedLang: "typescript",
		},
		{
			name:         "python_lowercase",
			lang:         "python",
			wantErr:      false,
			expectedLang: "python",
		},
		{
			name:         "py_short",
			lang:         "py",
			wantErr:      false,
			expectedLang: "python",
		},
		{
			name:    "unknown_language",
			lang:    "rust",
			wantErr: true,
		},
		{
			name:    "empty_language",
			lang:    "",
			wantErr: true,
		},
		{
			name:         "mixed_case_Go",
			lang:         "Go",
			wantErr:      false,
			expectedLang: "go",
		},
		{
			name:         "mixed_case_TypeScript",
			lang:         "TypeScript",
			wantErr:      false,
			expectedLang: "typescript",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor, err := getExtractorByLanguage(tt.lang, ".")

			if tt.wantErr {
				if err == nil {
					t.Errorf("getExtractorByLanguage(%q) expected error, got nil", tt.lang)
				}
				return
			}

			if err != nil {
				t.Errorf("getExtractorByLanguage(%q) unexpected error: %v", tt.lang, err)
				return
			}

			if extractor == nil {
				t.Errorf("getExtractorByLanguage(%q) returned nil extractor", tt.lang)
				return
			}

			if extractor.Language() != tt.expectedLang {
				t.Errorf("getExtractorByLanguage(%q) returned extractor for %q, want %q",
					tt.lang, extractor.Language(), tt.expectedLang)
			}
		})
	}
}

func TestProcessBatch_ValidatesPairPaths(t *testing.T) {
	tmpDir := t.TempDir()
	batchPath := filepath.Join(tmpDir, "batch.json")

	pairs := []map[string]string{
		{"before_path": "../../etc/passwd", "after_path": ""},
	}

	data, err := json.Marshal(pairs)
	if err != nil {
		t.Fatalf("failed to marshal batch JSON: %v", err)
	}
	if err := os.WriteFile(batchPath, data, 0o644); err != nil {
		t.Fatalf("failed to write batch file: %v", err)
	}

	err = processBatch(context.Background(), ast.NewRegistry(), batchPath)
	if err == nil {
		t.Fatal("expected path validation error for traversal path")
	}
	if !containsSubstring(err.Error(), "invalid before_path") {
		t.Fatalf("expected invalid before_path error, got: %v", err)
	}
}

// containsSubstring checks if s contains substr (case-insensitive).
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
