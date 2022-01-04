package main

import (
	"fmt"
	"os"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func main() {
	checks := scanner.GetRegisteredRules()
	fmt.Printf("Checks requiring linting: %d\n", len(checks))

	linter := &linter{}

	for _, check := range checks {
		linter.lint(check)
	}

	fmt.Printf("Checks requiring action:  %d\n", linter.count)
	os.Exit(linter.exitCode())
}
