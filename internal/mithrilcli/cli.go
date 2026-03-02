package mithrilcli

import (
	"fmt"
	"io"
	"strings"
)

var supportedCommands = []string{
	"scope-detector",
	"static-analysis",
	"ast-extractor",
	"call-graph",
	"data-flow",
	"compile-context",
}

// Run executes the mithril command line with the provided semantic version.
func Run(version string, args []string, stdout io.Writer, stderr io.Writer) error {
	command, commandArgs, ok := parseInvocation(args)
	if !ok {
		printUsage(stderr)
		return nil
	}

	switch command {
	case "version":
		_, _ = fmt.Fprintf(stdout, "mithril version %s\n", version)
		return nil
	case "help":
		printUsage(stdout)
		return nil
	}

	return executeCommand(command, commandArgs, stdout, stderr)
}

func parseInvocation(args []string) (string, []string, bool) {
	if len(args) == 0 {
		return "run-all", nil, true
	}

	first := strings.TrimSpace(args[0])
	if first == "" {
		return "run-all", args[1:], true
	}

	switch first {
	case "help", "-h", "--help":
		return "help", nil, true
	case "version", "-v", "--version":
		return "version", nil, true
	case "run-all":
		return "run-all", args[1:], true
	}

	if strings.HasPrefix(first, "-") {
		return "run-all", args, true
	}

	if isSupportedCommand(first) {
		return first, args[1:], true
	}

	return "", nil, false
}

func isSupportedCommand(command string) bool {
	for _, candidate := range supportedCommands {
		if candidate == command {
			return true
		}
	}
	return false
}

func executeCommand(command string, args []string, stdout io.Writer, stderr io.Writer) error {
	runner, ok := commandRunners[command]
	if !ok {
		return fmt.Errorf("unsupported command: %s", command)
	}
	return runner(args, stdout, stderr)
}

func printUsage(out io.Writer) {
	_, _ = fmt.Fprintf(out, "Mithril CLI\n\n")
	_, _ = fmt.Fprintf(out, "Usage:\n")
	_, _ = fmt.Fprintf(out, "  mithril [flags]\n")
	_, _ = fmt.Fprintf(out, "  mithril <command> [flags]\n\n")
	_, _ = fmt.Fprintf(out, "Main pipeline flags (use with `mithril`):\n")
	_, _ = fmt.Fprintf(out, "  --unstaged                     Analyze only unstaged + untracked changes\n")
	_, _ = fmt.Fprintf(out, "  --staged                       Analyze only staged changes\n")
	_, _ = fmt.Fprintf(out, "  --all-modified                 Analyze all modified files (staged + unstaged)\n")
	_, _ = fmt.Fprintf(out, "  --compare --base=main --head=HEAD  Compare two refs\n")
	_, _ = fmt.Fprintf(out, "  --output=.ring/codereview      Set output directory\n\n")
	_, _ = fmt.Fprintf(out, "Commands:\n")
	_, _ = fmt.Fprintf(out, "  run-all          Execute the full codereview pipeline (default)\n")
	_, _ = fmt.Fprintf(out, "  scope-detector   Detect changed files and language\n")
	_, _ = fmt.Fprintf(out, "  static-analysis  Run linters and static analyzers\n")
	_, _ = fmt.Fprintf(out, "  ast-extractor    Build semantic AST diff\n")
	_, _ = fmt.Fprintf(out, "  call-graph       Analyze call graph impact\n")
	_, _ = fmt.Fprintf(out, "  data-flow        Run security-focused data-flow analysis\n")
	_, _ = fmt.Fprintf(out, "  compile-context  Generate reviewer context files\n")
	_, _ = fmt.Fprintf(out, "  version          Print mithril version\n")
	_, _ = fmt.Fprintf(out, "  help             Show this help\n\n")
	_, _ = fmt.Fprintf(out, "Execution model:\n")
	_, _ = fmt.Fprintf(out, "  - Single binary with in-process subcommand dispatch\n")
	_, _ = fmt.Fprintf(out, "  - No sibling binary lookup and no `go run` fallback\n\n")
	_, _ = fmt.Fprintf(out, "Examples:\n")
	_, _ = fmt.Fprintf(out, "  mithril\n")
	_, _ = fmt.Fprintf(out, "  mithril --unstaged\n")
	_, _ = fmt.Fprintf(out, "  mithril --staged\n")
	_, _ = fmt.Fprintf(out, "  mithril --all-modified\n")
	_, _ = fmt.Fprintf(out, "  mithril --compare --base=main --head=HEAD\n")
	_, _ = fmt.Fprintf(out, "  mithril run-all --unstaged\n")
	_, _ = fmt.Fprintf(out, "  mithril scope-detector --base=main --head=HEAD\n")
	_, _ = fmt.Fprintf(out, "  mithril static-analysis --scope .ring/codereview/scope.json\n")
}
