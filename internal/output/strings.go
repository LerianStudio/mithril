package output

import "unicode"

// CapitalizeFirst capitalizes the first letter of a string.
// It is rune-safe: multi-byte leading runes (e.g. "über") are handled correctly.
// Returns the input unchanged when empty.
func CapitalizeFirst(s string) string {
	if s == "" {
		return s
	}
	runes := []rune(s)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}
