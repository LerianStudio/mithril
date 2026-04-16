# Mithril

**Reviewer-grade code analysis for git diffs.**

Mithril is a Go-based pipeline that turns a git diff into structured, reviewer-ready context. It detects what changed, runs the right linters for each language, extracts semantic AST diffs, builds call graphs, traces taint and data flow, and aggregates everything into JSON (and optionally Markdown) that downstream tools — code review bots, IDE plugins, CI gates — can consume directly.

It ships as a single binary with no plugin system and no sub-binary lookups. You point it at a diff, you get a directory of analysis artifacts. That is the entire user model.

---

## Why Mithril exists

Code review is bottlenecked by context-gathering. Reviewers spend most of their time figuring out what a change touches, what calls into it, what it might break, and whether anything looks risky — before they even start reading the patch. Mithril does that gathering for you, deterministically, on every diff.

The output is intentionally machine-first: every phase writes a self-contained JSON file you can feed to an LLM, a dashboard, a CI check, or a human reviewer. Nothing is hidden in stdout, and no phase requires the others to succeed.

---

## How the pipeline works

Mithril runs seven phases in order. Each phase reads the previous phases' artifacts and writes its own. If a phase has nothing to do (no changed files in its language, no required linter on PATH), it degrades gracefully and the pipeline continues.

| # | Phase | Output | What it does |
|---|-------|--------|--------------|
| 1 | `scope-detector` | `scope.json` | Detects modified, added, and deleted files from git, plus the primary language of the change |
| 2 | `static-analysis` | `static-analysis.json` | Runs linters per language: `golangci-lint`, `staticcheck`, `gosec` (Go); `tsc`, `eslint` (TypeScript); `ruff`, `mypy`, `pylint`, `bandit` (Python) |
| 3 | `ast-extractor` | `ast.json` | Produces semantic diffs of functions, types, variables, and imports. Native for Go; subprocess helpers in `py/` and `ts/` for the other languages |
| 4 | `call-graph` | `callgraph.json` | Maps caller and callee relationships, computes impact, flags virtual or interface-dispatch calls, and tracks test coverage of changed code |
| 5 | `data-flow` | `dataflow.json` | Tracks taint from sources (HTTP body/query/header, env vars, file and DB reads) to sinks (command exec, template injection, raw SQL), and reports nil-pointer risks at risk levels `critical`, `high`, `medium`, `low`, `info` |
| 6 | `compile-context` | `context.json` (+ optional `context.md`) | Aggregates every phase, records per-phase status (`not_run`, `completed`, `failed`, `empty`), and renders reviewer-ready templates |

The `run-all` command is the orchestrator. You almost always want this one.

---

## Requirements

Mithril itself only needs Go. Language coverage and linter coverage are opt-in: install what matches the code you analyze.

**Required**

- Go 1.26 or newer

**Optional, by language**

- **Python coverage** — Python 3.11+ and `py/requirements.txt` (currently `pyan3>=1.2.0`)
- **TypeScript coverage** — Node 20+ and `ts/package.json` dependencies (currently `typescript ^5.3.0`)

**Optional, by linter**

Each linter is invoked only if it is on `PATH` (Mithril probes with `which` first):

- Go: `golangci-lint`, `staticcheck`, `gosec`
- TypeScript: `tsc`, `eslint`
- Python: `ruff`, `mypy`, `pylint`, `bandit`

Missing tools are skipped silently and recorded in the phase output, so a partial install still produces useful results.

---

## Install

Build from source:

```bash
git clone https://github.com/lerianstudio/mithril.git
cd mithril
make build
```

The binary lands at `./bin/mithril`. To put it on your `PATH`:

```bash
make install
```

Other targets you'll use:

| Target | Purpose |
|--------|---------|
| `make all` | Format, vet, lint, test, and build |
| `make test` | Unit tests with the race detector |
| `make test-coverage` | Unit tests with coverage report |
| `make test-integration` | Integration tests (gated by the `integration` build tag) |
| `make fmt` | Apply `gofmt` |
| `make vet` | Run `go vet` |
| `make golangci-lint` | Run `golangci-lint` over the repo |
| `make lint` | Combined lint pass |
| `make clean` | Remove `bin/` and build artifacts |

---

## Quick start

The most common workflow is "analyze the diff between my branch and the default branch."

```bash
# Compare HEAD against the upstream default branch (auto-detected).
mithril
```

Mithril resolves the base ref by reading `git symbolic-ref refs/remotes/origin/HEAD`, then falls back to `main`, `master`, `trunk`, or `develop` in that order. Override it explicitly when you need to:

```bash
# Explicit base/head.
mithril --compare --base=main --head=HEAD
```

Other diff modes:

```bash
mithril --unstaged          # Working tree changes you haven't staged yet
mithril --staged            # What's in the index, ready to commit
mithril --all-modified      # Everything that differs from HEAD
```

Or analyze a specific list of files:

```bash
mithril --files "internal/lint/**.go,internal/ast/**.go"
mithril --files-from changed-files.txt
```

After any of these, look in `.ring/codereview/` for the JSON artifacts.

---

## Commands

`run-all` is the default; running `mithril` with no subcommand is equivalent to `mithril run-all`.

| Command | Purpose |
|---------|---------|
| `run-all` | Execute the full pipeline (default) |
| `scope-detector` | Detect changed files and primary language |
| `static-analysis` | Run linters and static analyzers |
| `ast-extractor` | Build the semantic AST diff |
| `call-graph` | Compute caller/callee relationships and impact |
| `data-flow` | Run taint and nil-pointer analysis |
| `compile-context` | Aggregate prior phases into reviewer context |
| `version` | Print the binary version |
| `help` | Show CLI help |

Individual phases are useful when you want to re-run one slice of the pipeline against a previously generated `scope.json`:

```bash
mithril scope-detector --base=main --head=HEAD
mithril static-analysis --scope .ring/codereview/scope.json
```

---

## Output artifacts

By default, every phase writes to `.ring/codereview/`. Override with `--output <dir>`.

| File | Producer | Contents |
|------|----------|----------|
| `scope.json` | `scope-detector` | Changed file list and primary language |
| `static-analysis.json` | `static-analysis` | Linter findings, per-tool status, timings |
| `ast.json` | `ast-extractor` | Semantic AST diff per file |
| `callgraph.json` | `call-graph` | Edges, impact set, test coverage of changed code |
| `dataflow.json` | `data-flow` | Taint paths, nil risks, risk-tagged findings |
| `context.json` | `compile-context` | Aggregated reviewer context across all phases |
| `context.md` | `compile-context` (optional) | Human-readable rendering of `context.json` |

JSON files are capped at 50 MB; AST files produced by Python and TypeScript helpers are capped at 10 MB. Phases hitting the cap report a truncated status rather than failing the pipeline.

---

## Configuration and flags

The flags below cover the most common cases. Run `mithril --help` (or `mithril <command> --help`) for the full list.

**Diff selection** (mutually exclusive)

- `--compare --base=<ref> --head=<ref>` — compare two refs (the default mode)
- `--staged` — staged changes only
- `--unstaged` — uncommitted working-tree changes
- `--all-modified` — everything that differs from `HEAD`
- `--files <glob1>,<glob2>` — explicit glob list
- `--files-from <path>` — read file paths from a text file

**Pipeline behavior**

- `--output <dir>` — output directory (default: `.ring/codereview`)
- `--skip <phase,phase,...>` — skip named phases
- `--timeout <duration>` — per-linter timeout (default: `5m`)
- `--linter-concurrency <n>` — parallel linter invocations (default: `4`)
- `-v`, `--verbose` — verbose logging; `run-all` propagates `-v` to every child phase

---

## Testing

The project ships three test suites. They run in CI on every push (`.github/workflows/test.yml`) on Go 1.26, Python 3.11, and Node 20.

```bash
# Go unit tests with the race detector
make test

# Go integration tests (build-tagged; exercises the shipped binary via exec.Command)
make test-integration

# Python helper tests
cd py && python -m pytest

# TypeScript helper smoke tests
cd ts && npm test
```

---

## Project structure

```
mithril/
├── main.go                       Entry point
├── internal/
│   ├── mithrilcli/              CLI parsing and in-process phase dispatch
│   ├── scope/                   Phase 1: changed-file detection
│   ├── lint/                    Phase 2: linter orchestration
│   ├── ast/                     Phase 3: semantic AST diff
│   ├── callgraph/               Phase 4: call-graph and impact analysis
│   ├── dataflow/                Phase 5: taint and nil-pointer analysis
│   ├── context/                 Phase 6: aggregation and templating
│   ├── git/                     Git diff helpers
│   ├── output/                  JSON/Markdown writers and size caps
│   ├── fileutil/                Path safety
│   └── procenv/                 Subprocess environment allowlist
├── py/                          Python AST and call-graph helpers
├── ts/                          TypeScript AST and call-graph helpers
├── testdata/                    Fixtures
└── .github/workflows/test.yml   CI: Go + Python 3.11 + Node 20
```

---

## Design principles

A few choices worth knowing about before you extend or embed Mithril:

- **Single binary, in-process dispatch.** No sub-binary lookups, no `go run` fallback. The dispatcher in `internal/mithrilcli/` calls phase code directly.
- **Graceful degradation.** Missing linters, missing language toolchains, and empty diffs are first-class outcomes. The pipeline continues and records what was skipped.
- **Path safety and process isolation.** All file paths are validated through `internal/fileutil/`, and subprocesses inherit only an allowlisted environment via `internal/procenv/`.
- **JSON-first output.** Every phase produces machine-readable JSON. Markdown rendering is opt-in and built on top of the same artifacts.

---

## Status and license

Mithril is in active development. The current branch is `develop`; `main` tracks releases.

License: TBD. No `LICENSE` file is present in the repository yet.
