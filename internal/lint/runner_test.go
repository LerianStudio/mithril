package lint

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubLinter is a minimal Linter used in Runner/selectTargets tests.
type stubLinter struct {
	name       string
	language   Language
	targetKind TargetKind
	run        func(ctx context.Context, dir string, targets []string) (*Result, error)
}

func (s *stubLinter) Name() string                      { return s.name }
func (s *stubLinter) Language() Language                { return s.language }
func (s *stubLinter) TargetKind() TargetKind            { return s.targetKind }
func (s *stubLinter) Available(ctx context.Context) bool { return true }
func (s *stubLinter) Version(ctx context.Context) (string, error) {
	return "stub", nil
}
func (s *stubLinter) Run(ctx context.Context, dir string, targets []string) (*Result, error) {
	if s.run != nil {
		return s.run(ctx, dir, targets)
	}
	return NewResult(), nil
}

func TestSelectTargets_GoPreferPackages(t *testing.T) {
	goLinter := &stubLinter{name: "gl", language: LanguageGo, targetKind: TargetKindPackages}
	targets := SelectTargets(goLinter,
		[]string{"a.go", "b.py"},
		[]string{"./internal/lint"},
	)
	require.Equal(t, []string{"./internal/lint"}, targets)
}

func TestSelectTargets_FiltersByExtension(t *testing.T) {
	pyLinter := &stubLinter{name: "bandit", language: LanguagePython, targetKind: TargetKindFiles}
	tsLinter := &stubLinter{name: "eslint", language: LanguageTypeScript, targetKind: TargetKindFiles}
	goLinterNoPkgs := &stubLinter{name: "gofile", language: LanguageGo, targetKind: TargetKindFiles}

	files := []string{"main.go", "src/app.py", "pkg/helpers.pyi", "web/app.tsx", "web/index.ts", "readme.md"}

	assert.Equal(t, []string{"src/app.py", "pkg/helpers.pyi"}, SelectTargets(pyLinter, files, nil))
	assert.Equal(t, []string{"web/app.tsx", "web/index.ts"}, SelectTargets(tsLinter, files, nil))
	assert.Equal(t, []string{"main.go"}, SelectTargets(goLinterNoPkgs, files, nil))
}

func TestSelectTargets_ProjectKindReturnsNil(t *testing.T) {
	l := &stubLinter{name: "x", language: LanguageGo, targetKind: TargetKindProject}
	assert.Nil(t, SelectTargets(l, []string{"a.go"}, []string{"./..."}))
}

func TestSelectTargets_PackagesEmptyFallsThrough(t *testing.T) {
	goLinter := &stubLinter{name: "gl", language: LanguageGo, targetKind: TargetKindPackages}
	// no packages -> nil
	assert.Nil(t, SelectTargets(goLinter, []string{"main.go"}, nil))
}

func TestSelectTargets_FileExtensionRoutingIsCaseInsensitive(t *testing.T) {
	l := &stubLinter{name: "l", language: LanguageTypeScript, targetKind: TargetKindFiles}
	files := []string{"App.TSX", "Main.JS"}
	assert.Equal(t, files, SelectTargets(l, files, nil))
}

func TestRunnerRun_PerLinterTimeoutIsolatesHang(t *testing.T) {
	// One linter blocks past the per-linter timeout. Others finish quickly.
	// Budget should be bounded by the per-linter timeout, not linter count.
	hanging := &stubLinter{
		name:     "hang",
		language: LanguageGo,
		run: func(ctx context.Context, dir string, targets []string) (*Result, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(5 * time.Second):
				return NewResult(), nil
			}
		},
	}
	fast1 := &stubLinter{
		name:     "fast1",
		language: LanguageGo,
		run: func(ctx context.Context, dir string, targets []string) (*Result, error) {
			r := NewResult()
			r.AddFinding(Finding{Tool: "fast1", Rule: "R1", Severity: SeverityInfo, File: "a.go", Line: 1, Message: "m"})
			return r, nil
		},
	}
	fast2 := &stubLinter{
		name:     "fast2",
		language: LanguageGo,
		run: func(ctx context.Context, dir string, targets []string) (*Result, error) {
			return NewResult(), nil
		},
	}

	runner := NewRunner()
	runner.PerLinterTimeout = 200 * time.Millisecond
	runner.MaxConcurrency = 4

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	res := runner.Run(ctx, "", []RunnerInput{
		{Linter: hanging},
		{Linter: fast1},
		{Linter: fast2},
	}, nil)
	elapsed := time.Since(start)

	require.Less(t, elapsed, 2*time.Second, "runner should not wait 2s; per-linter timeout is 200ms")
	assert.NotNil(t, res)
	assert.Len(t, res.Findings, 1, "fast1's finding survives")
	assert.Equal(t, "fast1", res.Findings[0].Tool)

	foundHangErr := false
	for _, e := range res.Errors {
		if containsAll(e, "hang", "deadline") || containsAll(e, "hang", "context") {
			foundHangErr = true
		}
	}
	assert.True(t, foundHangErr, "hang linter should yield a context error entry: %v", res.Errors)
}

func containsAll(s string, subs ...string) bool {
	for _, x := range subs {
		if !strings.Contains(s, x) {
			return false
		}
	}
	return true
}

func TestRunnerRun_RunsInParallel(t *testing.T) {
	var active, maxActive int32
	sleepy := func() *stubLinter {
		return &stubLinter{
			name:     "s",
			language: LanguageGo,
			run: func(ctx context.Context, dir string, targets []string) (*Result, error) {
				a := atomic.AddInt32(&active, 1)
				for {
					m := atomic.LoadInt32(&maxActive)
					if a <= m || atomic.CompareAndSwapInt32(&maxActive, m, a) {
						break
					}
				}
				time.Sleep(50 * time.Millisecond)
				atomic.AddInt32(&active, -1)
				return NewResult(), nil
			},
		}
	}

	runner := NewRunner()
	runner.MaxConcurrency = 3
	inputs := []RunnerInput{
		{Linter: sleepy()},
		{Linter: sleepy()},
		{Linter: sleepy()},
	}
	runner.Run(context.Background(), "", inputs, nil)
	assert.GreaterOrEqual(t, atomic.LoadInt32(&maxActive), int32(2), "expected concurrent execution")
}

func TestRunnerRun_ErrorFromLinter(t *testing.T) {
	failing := &stubLinter{
		name:     "broken",
		language: LanguageGo,
		run: func(ctx context.Context, dir string, targets []string) (*Result, error) {
			return nil, errors.New("boom")
		},
	}
	runner := NewRunner()
	runner.PerLinterTimeout = time.Second
	res := runner.Run(context.Background(), "", []RunnerInput{{Linter: failing}}, nil)
	require.NotEmpty(t, res.Errors)
	assert.Contains(t, res.Errors[0], "broken")
	assert.Contains(t, res.Errors[0], "boom")
}

func TestDeduplicate_KeepsHigherSeverity(t *testing.T) {
	r := NewResult()
	r.AddFinding(Finding{Tool: "a", Severity: SeverityWarning, File: "f.go", Line: 1, Message: "dup"})
	r.AddFinding(Finding{Tool: "b", Severity: SeverityHigh, File: "f.go", Line: 1, Message: "dup"})
	r.AddFinding(Finding{Tool: "c", Severity: SeverityInfo, File: "g.go", Line: 1, Message: "uniq"})

	Deduplicate(r)

	require.Len(t, r.Findings, 2)
	// Higher severity kept
	var dupTool string
	for _, f := range r.Findings {
		if f.File == "f.go" {
			dupTool = f.Tool
		}
	}
	assert.Equal(t, "b", dupTool)
	assert.Equal(t, 1, r.Summary.High)
	assert.Equal(t, 1, r.Summary.Info)
	assert.Equal(t, 0, r.Summary.Warning)
}

func TestSeverityRank_Order(t *testing.T) {
	assert.Greater(t, SeverityRank(SeverityCritical), SeverityRank(SeverityHigh))
	assert.Greater(t, SeverityRank(SeverityHigh), SeverityRank(SeverityWarning))
	assert.Greater(t, SeverityRank(SeverityWarning), SeverityRank(SeverityInfo))
	assert.Equal(t, 0, SeverityRank(Severity("nope")))
}

func TestSummary_IncrementSummary(t *testing.T) {
	var s Summary
	assert.True(t, s.IncrementSummary(SeverityCritical))
	assert.True(t, s.IncrementSummary(SeverityHigh))
	assert.True(t, s.IncrementSummary(SeverityWarning))
	assert.True(t, s.IncrementSummary(SeverityInfo))
	assert.False(t, s.IncrementSummary(Severity("zzz")))
	assert.Equal(t, Summary{Critical: 1, High: 1, Warning: 1, Info: 1, Unknown: 1}, s)
}
