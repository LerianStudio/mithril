package main

import (
	"sort"
	"testing"
)

func TestNormalizeCallgraphLanguage(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// Go variants
		{name: "go lowercase", input: "go", expected: "go"},
		{name: "golang alias", input: "golang", expected: "go"},
		{name: "Go mixed case", input: "Go", expected: "go"},
		{name: "GOLANG uppercase", input: "GOLANG", expected: "go"},

		// TypeScript/JavaScript variants
		{name: "typescript", input: "typescript", expected: "typescript"},
		{name: "ts alias", input: "ts", expected: "typescript"},
		{name: "TypeScript mixed case", input: "TypeScript", expected: "typescript"},
		{name: "javascript maps to typescript", input: "javascript", expected: "typescript"},
		{name: "js maps to typescript", input: "js", expected: "typescript"},

		// Python variants
		{name: "python", input: "python", expected: "python"},
		{name: "py alias", input: "py", expected: "python"},
		{name: "Python mixed case", input: "Python", expected: "python"},

		// Edge cases
		{name: "empty string", input: "", expected: ""},
		{name: "mixed returns empty", input: "mixed", expected: ""},
		{name: "unknown returns empty", input: "unknown", expected: ""},
		{name: "unsupported returns normalized lowercase", input: "rust", expected: "rust"},
		{name: "whitespace trimmed", input: "  go  ", expected: "go"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeCallgraphLanguage(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeCallgraphLanguage(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestOrderCallgraphLanguages(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "go before typescript before python",
			input:    []string{"python", "typescript", "go"},
			expected: []string{"go", "typescript", "python"},
		},
		{
			name:     "single language unchanged",
			input:    []string{"go"},
			expected: []string{"go"},
		},
		{
			name:     "already ordered stays the same",
			input:    []string{"go", "typescript", "python"},
			expected: []string{"go", "typescript", "python"},
		},
		{
			name:     "unknown languages sort after known ones",
			input:    []string{"rust", "go", "python"},
			expected: []string{"go", "python", "rust"},
		},
		{
			name:     "multiple unknown languages sort alphabetically",
			input:    []string{"zig", "rust", "go"},
			expected: []string{"go", "rust", "zig"},
		},
		{
			name:     "empty slice",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "two languages only",
			input:    []string{"python", "go"},
			expected: []string{"go", "python"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Copy to avoid mutating test data
			input := make([]string, len(tt.input))
			copy(input, tt.input)

			orderCallgraphLanguages(input)

			if len(input) != len(tt.expected) {
				t.Fatalf("orderCallgraphLanguages() length = %d, want %d", len(input), len(tt.expected))
			}

			for i := range input {
				if input[i] != tt.expected[i] {
					t.Errorf("orderCallgraphLanguages()[%d] = %q, want %q (full: %v)", i, input[i], tt.expected[i], input)
					break
				}
			}
		})
	}

	// Verify stability: equal-priority items preserve relative order
	t.Run("stable sort for equal priorities", func(t *testing.T) {
		input := []string{"beta", "alpha", "go"}
		orderCallgraphLanguages(input)

		// "go" should be first (priority 0), then "alpha" < "beta" alphabetically
		if input[0] != "go" {
			t.Errorf("expected go first, got %q", input[0])
		}
		// Unknown languages with same priority should be sorted alphabetically
		if !sort.StringsAreSorted(input[1:]) {
			t.Errorf("unknown languages should be sorted alphabetically: %v", input[1:])
		}
	})
}
