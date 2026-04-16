package lint

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

type mockRegistryLinter struct {
	name      string
	language  Language
	available bool
}

func (m *mockRegistryLinter) Name() string {
	return m.name
}

func (m *mockRegistryLinter) Language() Language {
	return m.language
}

func (m *mockRegistryLinter) Available(ctx context.Context) bool {
	return m.available
}

func (m *mockRegistryLinter) Version(ctx context.Context) (string, error) {
	return "test", nil
}

func (m *mockRegistryLinter) Run(ctx context.Context, projectDir string, files []string) (*Result, error) {
	return &Result{}, nil
}

func TestRegistryRegisterAndGetLinters(t *testing.T) {
	registry := NewRegistry()
	goLinter := &mockRegistryLinter{name: "go-linter", language: LanguageGo, available: true}

	registry.Register(goLinter)

	linters := registry.GetLinters(LanguageGo)
	require.Len(t, linters, 1)
	require.Equal(t, "go-linter", linters[0].Name())
	require.Empty(t, registry.GetLinters(LanguagePython))
}

func TestRegistryGetAvailableLinters(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&mockRegistryLinter{name: "available", language: LanguageGo, available: true})
	registry.Register(&mockRegistryLinter{name: "unavailable", language: LanguageGo, available: false})

	available := registry.GetAvailableLinters(context.Background(), LanguageGo)
	require.Len(t, available, 1)
	require.Equal(t, "available", available[0].Name())
}
