package ast

import "testing"

func TestRegistryRegister_NilExtractorIsIgnored(t *testing.T) {
	r := NewRegistry()
	r.Register(nil)

	if len(r.extractors) != 0 {
		t.Fatalf("expected nil extractor registration to be ignored, got %d entries", len(r.extractors))
	}
}

func TestComputeSummary_CountsModifiedEntities(t *testing.T) {
	summary := ComputeSummary(
		[]FunctionDiff{{Name: "OldName", ChangeType: ChangeModified}},
		[]TypeDiff{{Name: "User", ChangeType: ChangeModified}},
		[]VarDiff{{Name: "Config", ChangeType: ChangeModified}},
		[]ImportDiff{{Path: "fmt", ChangeType: ChangeAdded}},
	)

	if summary.FunctionsModified != 1 {
		t.Fatalf("FunctionsModified = %d, want 1", summary.FunctionsModified)
	}
	if summary.TypesModified != 1 {
		t.Fatalf("TypesModified = %d, want 1", summary.TypesModified)
	}
	if summary.VariablesModified != 1 {
		t.Fatalf("VariablesModified = %d, want 1", summary.VariablesModified)
	}
	if summary.ImportsAdded != 1 {
		t.Fatalf("ImportsAdded = %d, want 1", summary.ImportsAdded)
	}
}
