package main

import (
	"fmt"
	"os"

	_ "github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func main() {
	checks := scanner.GetRegisteredChecks()
	fmt.Printf("%d checks require linting\n", len(checks))

	linter := &linter{}

	for _, check := range checks {
		linter.lint(check)
	}

	fmt.Printf("%d checks require attention\n", linter.count)
	os.Exit(linter.exitCode)
}
