package output

import "testing"

func TestCapitalizeFirst(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "empty", input: "", expected: ""},
		{name: "single lowercase", input: "a", expected: "A"},
		{name: "single uppercase", input: "A", expected: "A"},
		{name: "ascii word", input: "hello", expected: "Hello"},
		{name: "already capitalized", input: "Hello", expected: "Hello"},
		{name: "all uppercase", input: "HELLO", expected: "HELLO"},
		{name: "unicode umlaut", input: "über", expected: "Über"},
		{name: "unicode cyrillic", input: "привет", expected: "Привет"},
		{name: "numeric prefix", input: "123abc", expected: "123abc"},
		{name: "rest preserved", input: "aBC", expected: "ABC"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CapitalizeFirst(tt.input)
			if got != tt.expected {
				t.Errorf("CapitalizeFirst(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
