package callgraph

import (
	"testing"
)

func TestNewAnalyzer(t *testing.T) {
	workDir := t.TempDir()

	tests := []struct {
		name     string
		language string
		wantErr  bool
		wantLang string
	}{
		{name: "go", language: "go", wantErr: false, wantLang: "go"},
		{name: "golang alias", language: "golang", wantErr: false, wantLang: "go"},
		{name: "Go mixed case", language: "Go", wantErr: false, wantLang: "go"},
		{name: "GOLANG uppercase", language: "GOLANG", wantErr: false, wantLang: "go"},
		{name: "typescript", language: "typescript", wantErr: false, wantLang: "typescript"},
		{name: "ts alias", language: "ts", wantErr: false, wantLang: "typescript"},
		{name: "python", language: "python", wantErr: false, wantLang: "python"},
		{name: "py alias", language: "py", wantErr: false, wantLang: "python"},
		{name: "unsupported language", language: "rust", wantErr: true},
		{name: "empty string", language: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer, err := NewAnalyzer(tt.language, workDir)
			if tt.wantErr {
				if err == nil {
					t.Errorf("NewAnalyzer(%q) expected error, got nil", tt.language)
				}
				if analyzer != nil {
					t.Errorf("NewAnalyzer(%q) expected nil analyzer on error", tt.language)
				}
				return
			}

			if err != nil {
				t.Errorf("NewAnalyzer(%q) unexpected error: %v", tt.language, err)
				return
			}
			if analyzer == nil {
				t.Errorf("NewAnalyzer(%q) returned nil analyzer", tt.language)
			}
		})
	}
}

func TestNewAnalyzer_ReturnsCorrectType(t *testing.T) {
	workDir := t.TempDir()

	t.Run("go returns GoAnalyzer", func(t *testing.T) {
		analyzer, err := NewAnalyzer("go", workDir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := analyzer.(*GoAnalyzer); !ok {
			t.Errorf("expected *GoAnalyzer, got %T", analyzer)
		}
	})

	t.Run("typescript returns TypeScriptAnalyzer", func(t *testing.T) {
		analyzer, err := NewAnalyzer("typescript", workDir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := analyzer.(*TypeScriptAnalyzer); !ok {
			t.Errorf("expected *TypeScriptAnalyzer, got %T", analyzer)
		}
	})

	t.Run("python returns PythonAnalyzer", func(t *testing.T) {
		analyzer, err := NewAnalyzer("python", workDir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := analyzer.(*PythonAnalyzer); !ok {
			t.Errorf("expected *PythonAnalyzer, got %T", analyzer)
		}
	})
}

func TestNormalizeLanguage(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "go lowercase", input: "go", expected: "go"},
		{name: "golang alias", input: "golang", expected: "go"},
		{name: "Go mixed case", input: "Go", expected: "go"},
		{name: "GO uppercase", input: "GO", expected: "go"},
		{name: "GOLANG uppercase", input: "GOLANG", expected: "go"},
		{name: "typescript lowercase", input: "typescript", expected: "typescript"},
		{name: "ts alias", input: "ts", expected: "typescript"},
		{name: "TypeScript mixed case", input: "TypeScript", expected: "typescript"},
		{name: "TS uppercase", input: "TS", expected: "typescript"},
		{name: "python lowercase", input: "python", expected: "python"},
		{name: "py alias", input: "py", expected: "python"},
		{name: "Python mixed case", input: "Python", expected: "python"},
		{name: "PY uppercase", input: "PY", expected: "python"},
		{name: "unknown returns empty", input: "rust", expected: ""},
		{name: "empty returns empty", input: "", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeLanguage(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizeLanguage(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsSupported(t *testing.T) {
	tests := []struct {
		name     string
		language string
		expected bool
	}{
		{name: "go", language: "go", expected: true},
		{name: "golang", language: "golang", expected: true},
		{name: "Go mixed case", language: "Go", expected: true},
		{name: "typescript", language: "typescript", expected: true},
		{name: "ts", language: "ts", expected: true},
		{name: "python", language: "python", expected: true},
		{name: "py", language: "py", expected: true},
		{name: "rust unsupported", language: "rust", expected: false},
		{name: "java unsupported", language: "java", expected: false},
		{name: "empty string", language: "", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSupported(tt.language)
			if result != tt.expected {
				t.Errorf("IsSupported(%q) = %v, want %v", tt.language, result, tt.expected)
			}
		})
	}
}

func TestSupportedLanguages(t *testing.T) {
	languages := SupportedLanguages()

	if len(languages) == 0 {
		t.Fatal("SupportedLanguages() returned empty list")
	}

	// Should contain all known identifiers including aliases
	expected := map[string]bool{
		"go":         false,
		"golang":     false,
		"typescript": false,
		"ts":         false,
		"python":     false,
		"py":         false,
	}

	for _, lang := range languages {
		if _, ok := expected[lang]; ok {
			expected[lang] = true
		}
	}

	for lang, found := range expected {
		if !found {
			t.Errorf("SupportedLanguages() missing %q", lang)
		}
	}
}

func TestSupportedLanguagesNormalized(t *testing.T) {
	languages := SupportedLanguagesNormalized()

	if len(languages) != 3 {
		t.Errorf("SupportedLanguagesNormalized() returned %d languages, want 3", len(languages))
	}

	expected := map[string]bool{"go": false, "typescript": false, "python": false}
	for _, lang := range languages {
		if _, ok := expected[lang]; ok {
			expected[lang] = true
		}
	}

	for lang, found := range expected {
		if !found {
			t.Errorf("SupportedLanguagesNormalized() missing %q", lang)
		}
	}
}
