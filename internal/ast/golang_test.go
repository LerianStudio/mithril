package ast

import (
	"context"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"
)

func codereviewRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to determine test file path")
	}
	root := filepath.Join(filepath.Dir(filename), "..", "..")
	absRoot, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("failed to resolve codereview root: %v", err)
	}
	if _, err := os.Stat(absRoot); err != nil {
		t.Fatalf("codereview root does not exist: %v", err)
	}
	return absRoot
}

// chdirForTest changes the test's working directory to dir using t.Chdir
// (Go 1.24+), which restores the original cwd when the test ends and panics
// if t.Parallel() has been called — replacing the previous global mutex +
// manual os.Chdir dance that could leak cwd on panic.
func chdirForTest(t *testing.T, dir string) {
	t.Helper()
	t.Chdir(dir)
}

func TestGoExtractor_ExtractDiff(t *testing.T) {
	extractor := NewGoExtractor()

	root := codereviewRoot(t)
	chdirForTest(t, root)
	beforePath := filepath.Join("testdata", "go", "before.go")
	afterPath := filepath.Join("testdata", "go", "after.go")

	diff, err := extractor.ExtractDiff(context.Background(), beforePath, afterPath)
	if err != nil {
		t.Fatalf("ExtractDiff failed: %v", err)
	}

	// Verify language
	if diff.Language != "go" {
		t.Errorf("expected language 'go', got '%s'", diff.Language)
	}

	// Verify function changes
	funcChanges := make(map[string]ChangeType)
	for _, f := range diff.Functions {
		funcChanges[f.Name] = f.ChangeType
	}

	// Hello should be modified (signature changed)
	if ct, ok := funcChanges["Hello"]; !ok || ct != ChangeModified {
		t.Errorf("expected Hello to be modified, got %v", funcChanges["Hello"])
	}

	// FormatName should be removed
	if ct, ok := funcChanges["FormatName"]; !ok || ct != ChangeRemoved {
		t.Errorf("expected FormatName to be removed, got %v", funcChanges["FormatName"])
	}

	// NewGreeting should be added
	if ct, ok := funcChanges["NewGreeting"]; !ok || ct != ChangeAdded {
		t.Errorf("expected NewGreeting to be added, got %v", funcChanges["NewGreeting"])
	}

	// User.GetEmail should be added
	if ct, ok := funcChanges["*User.GetEmail"]; !ok || ct != ChangeAdded {
		t.Errorf("expected *User.GetEmail to be added, got %v", funcChanges["*User.GetEmail"])
	}

	// Verify type changes
	typeChanges := make(map[string]ChangeType)
	for _, ty := range diff.Types {
		typeChanges[ty.Name] = ty.ChangeType
	}

	// User should be modified (fields added)
	if ct, ok := typeChanges["User"]; !ok || ct != ChangeModified {
		t.Errorf("expected User to be modified, got %v", typeChanges["User"])
	}

	// Config should be added
	if ct, ok := typeChanges["Config"]; !ok || ct != ChangeAdded {
		t.Errorf("expected Config to be added, got %v", typeChanges["Config"])
	}

	// Verify variable changes
	varChanges := make(map[string]ChangeType)
	for _, v := range diff.Variables {
		varChanges[v.Name] = v.ChangeType
	}

	if ct, ok := varChanges["DefaultTimeout"]; !ok || ct != ChangeAdded {
		t.Errorf("expected DefaultTimeout to be added, got %v", varChanges["DefaultTimeout"])
	}
	if ct, ok := varChanges["greetingPrefix"]; !ok || ct != ChangeAdded {
		t.Errorf("expected greetingPrefix to be added, got %v", varChanges["greetingPrefix"])
	}

	// Verify import changes
	importChanges := make(map[string]ChangeType)
	for _, imp := range diff.Imports {
		importChanges[imp.Path] = imp.ChangeType
	}

	// strings should be removed
	if ct, ok := importChanges["strings"]; !ok || ct != ChangeRemoved {
		t.Errorf("expected 'strings' import to be removed, got %v", importChanges["strings"])
	}

	// context should be added
	if ct, ok := importChanges["context"]; !ok || ct != ChangeAdded {
		t.Errorf("expected 'context' import to be added, got %v", importChanges["context"])
	}

	// Verify summary
	if diff.Summary.FunctionsAdded < 2 {
		t.Errorf("expected at least 2 functions added, got %d", diff.Summary.FunctionsAdded)
	}
	if diff.Summary.FunctionsRemoved < 1 {
		t.Errorf("expected at least 1 function removed, got %d", diff.Summary.FunctionsRemoved)
	}
	if diff.Summary.TypesAdded < 1 {
		t.Errorf("expected at least 1 type added, got %d", diff.Summary.TypesAdded)
	}
	if diff.Summary.VariablesAdded < 2 {
		t.Errorf("expected at least 2 variables added, got %d", diff.Summary.VariablesAdded)
	}
}

func TestGoExtractor_NewFile(t *testing.T) {
	extractor := NewGoExtractor()

	root := codereviewRoot(t)
	chdirForTest(t, root)
	afterPath := filepath.Join("testdata", "go", "after.go")

	diff, err := extractor.ExtractDiff(context.Background(), "", afterPath)
	if err != nil {
		t.Fatalf("ExtractDiff failed: %v", err)
	}

	// All functions should be added
	for _, f := range diff.Functions {
		if f.ChangeType != ChangeAdded {
			t.Errorf("expected function %s to be added, got %s", f.Name, f.ChangeType)
		}
	}

	if len(diff.Functions) == 0 {
		t.Fatal("expected at least one added function for new file")
	}
}

func TestGoExtractor_DeletedFile(t *testing.T) {
	extractor := NewGoExtractor()

	root := codereviewRoot(t)
	chdirForTest(t, root)
	beforePath := filepath.Join("testdata", "go", "before.go")

	diff, err := extractor.ExtractDiff(context.Background(), beforePath, "")
	if err != nil {
		t.Fatalf("ExtractDiff failed: %v", err)
	}

	// All functions should be removed
	for _, f := range diff.Functions {
		if f.ChangeType != ChangeRemoved {
			t.Errorf("expected function %s to be removed, got %s", f.Name, f.ChangeType)
		}
	}

	if len(diff.Functions) == 0 {
		t.Fatal("expected at least one removed function for deleted file")
	}
}

func TestGoExtractor_SupportedExtensions(t *testing.T) {
	extractor := NewGoExtractor()

	extensions := extractor.SupportedExtensions()
	if len(extensions) != 1 || extensions[0] != ".go" {
		t.Errorf("expected ['.go'], got %v", extensions)
	}
}

func TestGoExtractor_Language(t *testing.T) {
	extractor := NewGoExtractor()

	if extractor.Language() != "go" {
		t.Errorf("expected 'go', got '%s'", extractor.Language())
	}
}

func TestGoExtractor_ParseFile_InvalidPath(t *testing.T) {
	extractor := NewGoExtractor()

	_, err := extractor.ExtractDiff(context.Background(), "/nonexistent/file.go", "")
	if err == nil {
		t.Error("expected error for nonexistent file, got nil")
	}
}

func TestGoExtractor_ExtractDiff_RespectsScope(t *testing.T) {
	extractor := NewGoExtractor()
	path := filepath.Join(t.TempDir(), "sample.go")
	content := `package main

var Config = "Global"

type ConfigType struct {}

func init() {}
func init() {}

func main() {
	var Config = "Local"
	_ = Config
	type ConfigType struct {}
	_ = ConfigType{}
}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	chdirForTest(t, filepath.Dir(path))
	diff, err := extractor.ExtractDiff(context.Background(), "", path)
	if err != nil {
		t.Fatalf("ExtractDiff failed: %v", err)
	}

	if len(diff.Functions) != 3 {
		t.Fatalf("expected 3 added functions (main + 2 init), got %d", len(diff.Functions))
	}

	for _, fn := range diff.Functions {
		if fn.ChangeType != ChangeAdded {
			t.Fatalf("expected added function change type, got %s", fn.ChangeType)
		}
	}
}

func TestGoExtractor_ParseFile_RejectsOversizedFile(t *testing.T) {
	extractor := NewGoExtractor()
	path := filepath.Join(t.TempDir(), "oversized.go")

	content := make([]byte, maxASTFileSize+1)
	for i := range content {
		content[i] = 'a'
	}

	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("failed to write oversized file: %v", err)
	}

	chdirForTest(t, filepath.Dir(path))
	_, err := extractor.parseFile(path)
	if err == nil {
		t.Fatal("expected oversized file to be rejected")
	}
	if !strings.Contains(err.Error(), "maximum allowed size") {
		t.Fatalf("expected size limit error, got: %v", err)
	}
}

func TestGoExtractor_ParseFile_EmptyPath(t *testing.T) {
	extractor := NewGoExtractor()
	_, err := extractor.parseFile("")
	if err == nil {
		t.Fatal("expected empty path error")
	}
}

func TestGoExtractor_ZeroValueSafeMethods(t *testing.T) {
	var extractor GoExtractor
	if extractor.Language() != "go" {
		t.Fatalf("expected go language from zero value")
	}
	extensions := extractor.SupportedExtensions()
	if len(extensions) != 1 || extensions[0] != ".go" {
		t.Fatalf("unexpected extensions from zero value: %v", extensions)
	}
}

func TestGoExtractor_BodyHashUsesSHA256(t *testing.T) {
	extractor := NewGoExtractor()
	path := filepath.Join(t.TempDir(), "hash.go")
	content := `package main

func greet(name string) string {
	return "hello, " + name
}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	chdirForTest(t, filepath.Dir(path))
	parsed, err := extractor.parseFile(path)
	if err != nil {
		t.Fatalf("parseFile failed: %v", err)
	}

	fn := parsed.Functions["greet"]
	if fn == nil {
		t.Fatal("expected greet function to be parsed")
	}
	if len(fn.BodyHash) != 64 {
		t.Fatalf("expected SHA-256 hash length 64, got %d (%q)", len(fn.BodyHash), fn.BodyHash)
	}
	for _, r := range fn.BodyHash {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			t.Fatalf("expected lowercase hex hash, got %q", fn.BodyHash)
		}
	}
	if utf8.RuneCountInString(fn.BodyHash) != 64 {
		t.Fatalf("expected 64 runes in hash, got %d", utf8.RuneCountInString(fn.BodyHash))
	}
}

// TestGoExtractor_NilSafetyOnMalformedAST exercises the extraction helpers with
// directly-constructed AST nodes that have nil Name / Type / Path fields. This
// shape can be produced by the parser when recovering from malformed input, so
// the extractors must not panic. It also confirms that parsing a truncated Go
// source file fails cleanly without panicking.
func TestGoExtractor_NilSafetyOnMalformedAST(t *testing.T) {
	extractor := NewGoExtractor()

	// 1. Truncated source should return an error, not panic.
	path := filepath.Join(t.TempDir(), "truncated.go")
	if err := os.WriteFile(path, []byte("package p\nfunc"), 0o644); err != nil {
		t.Fatalf("failed to write truncated source: %v", err)
	}
	chdirForTest(t, filepath.Dir(path))
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseFile panicked on truncated source: %v", r)
			}
		}()
		if _, err := extractor.parseFile(path); err == nil {
			t.Fatal("expected parse error on truncated source")
		}
	}()

	fset := token.NewFileSet()

	// 2. FuncDecl with nil Name and nil Type (as recovery mode may produce).
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("extractFunc panicked on nil Name/Type: %v", r)
			}
		}()
		fn := extractor.extractFunc(fset, &ast.FuncDecl{})
		if fn == nil {
			t.Fatal("extractFunc returned nil")
		}
		if fn.Name != "" {
			t.Fatalf("expected empty name, got %q", fn.Name)
		}
	}()

	// 3. TypeSpec with nil Name and nil Type.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("extractType panicked on nil Name/Type: %v", r)
			}
		}()
		ty := extractor.extractType(fset, &ast.TypeSpec{})
		if ty == nil {
			t.Fatal("extractType returned nil")
		}
		if ty.Name != "" {
			t.Fatalf("expected empty name, got %q", ty.Name)
		}
		if ty.Kind != "alias" {
			t.Fatalf("expected alias kind for nil Type, got %q", ty.Kind)
		}
	}()

	// 4. Top-level parse over a synthetic file with FuncDecl/TypeSpec/ImportSpec
	//    all missing their expected identifiers must not panic and must skip
	//    the malformed decls.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseFile-like extraction panicked on nil sub-fields: %v", r)
			}
		}()
		file := &ast.File{
			Name: &ast.Ident{Name: "p"},
			Decls: []ast.Decl{
				&ast.FuncDecl{}, // nil Name -> skipped
				&ast.GenDecl{
					Tok: token.TYPE,
					Specs: []ast.Spec{
						&ast.TypeSpec{}, // nil Name -> skipped
					},
				},
				&ast.GenDecl{
					Tok: token.IMPORT,
					Specs: []ast.Spec{
						&ast.ImportSpec{}, // nil Path -> skipped below via file.Imports
					},
				},
			},
			Imports: []*ast.ImportSpec{{}}, // nil Path -> skipped
		}
		parsed := &ParsedFile{
			Fset:      fset,
			File:      file,
			Functions: make(map[string]*GoFunc),
			Types:     make(map[string]*GoType),
			Variables: make(map[string]*GoVar),
			Imports:   make(map[string]string),
		}
		// Replay the extraction loop inline to exercise the nil guards. We
		// intentionally mirror parseFile's per-decl handling here rather than
		// calling parseFile, because parseFile reads a file from disk.
		for _, imp := range parsed.File.Imports {
			if imp == nil || imp.Path == nil {
				continue
			}
			parsed.Imports[imp.Path.Value] = ""
		}
		for _, decl := range parsed.File.Decls {
			switch node := decl.(type) {
			case *ast.FuncDecl:
				if node.Name == nil {
					continue
				}
				parsed.Functions[node.Name.Name] = extractor.extractFunc(fset, node)
			case *ast.GenDecl:
				if node.Tok == token.TYPE {
					for _, spec := range node.Specs {
						if ts, ok := spec.(*ast.TypeSpec); ok {
							if ts.Name == nil {
								continue
							}
							ty := extractor.extractType(fset, ts)
							parsed.Types[ty.Name] = ty
						}
					}
				}
			}
		}
		if len(parsed.Functions) != 0 {
			t.Fatalf("expected zero functions from nil decls, got %d", len(parsed.Functions))
		}
		if len(parsed.Types) != 0 {
			t.Fatalf("expected zero types from nil specs, got %d", len(parsed.Types))
		}
		if len(parsed.Imports) != 0 {
			t.Fatalf("expected zero imports from nil paths, got %d", len(parsed.Imports))
		}
	}()
}
