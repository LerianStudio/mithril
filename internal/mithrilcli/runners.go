package mithrilcli

import (
	"io"
)

type commandRunner func(args []string, stdout io.Writer, stderr io.Writer) error

var commandRunners = map[string]commandRunner{
	"run-all":         runAllInProcess,
	"scope-detector":  runScopeDetector,
	"static-analysis": runStaticAnalysis,
	"ast-extractor":   runAstExtractor,
	"call-graph":      runCallGraph,
	"data-flow":       runDataFlow,
	"compile-context": runCompileContext,
}

func runAllInProcess(args []string, stdout io.Writer, stderr io.Writer) error {
	return runAll(args, stdout, stderr)
}
