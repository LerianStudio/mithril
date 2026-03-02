package main

import (
	"fmt"
	"os"

	"github.com/lerianstudio/mithril/internal/mithrilcli"
)

var version = "dev"

func main() {
	if err := mithrilcli.Run(version, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
