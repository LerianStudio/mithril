// Minimal smoke tests for TypeScript subprocess entry points.
// Goal: ensure each compiled script loads without throwing and emits
// well-formed JSON on stdout for a trivial valid input. Not a coverage
// substitute — this is a regression gate so "TS broken" stops being invisible.

import { spawnSync } from "node:child_process"
import { existsSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { dirname, join } from "node:path"
import test from "node:test"
import assert from "node:assert/strict"

const here = dirname(fileURLToPath(import.meta.url))
const distAst = join(here, "dist", "ast-extractor.js")
const distCallGraph = join(here, "dist", "call-graph.js")
const sample = join(here, "testdata", "sample.ts")

function runNode(script, args) {
  const res = spawnSync(process.execPath, [script, ...args], {
    encoding: "utf8",
  })
  return res
}

test("dist artifacts exist (run `npm run build` first)", () => {
  assert.ok(existsSync(distAst), `missing ${distAst}`)
  assert.ok(existsSync(distCallGraph), `missing ${distCallGraph}`)
  assert.ok(existsSync(sample), `missing fixture ${sample}`)
})

test("ast-extractor emits valid JSON for a trivial added file", () => {
  const { status, stdout, stderr } = runNode(distAst, [
    "--before",
    "",
    "--after",
    sample,
  ])
  assert.equal(status, 0, `non-zero exit: ${stderr}`)
  const parsed = JSON.parse(stdout)
  assert.equal(parsed.language, "typescript")
  assert.ok(Array.isArray(parsed.functions))
  assert.ok(parsed.summary, "summary present")
})

test("call-graph emits valid JSON for the fixture file", () => {
  const { status, stdout, stderr } = runNode(distCallGraph, [sample])
  assert.equal(status, 0, `non-zero exit: ${stderr}`)
  const parsed = JSON.parse(stdout)
  assert.ok(Array.isArray(parsed.functions))
})

test("call-graph rejects paths outside --base-dir", () => {
  // Pass the project root as base-dir; attempt to analyze a path in /tmp.
  const outside = join("/tmp", "definitely-not-in-repo.ts")
  const { status, stderr } = runNode(distCallGraph, [
    "--base-dir",
    here,
    outside,
  ])
  assert.notEqual(status, 0, "expected non-zero exit for out-of-base path")
  assert.match(stderr, /escapes base directory/)
})
