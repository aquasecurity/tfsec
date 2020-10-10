package main

import (
	_ "github.com/spf13/cobra"
	_ "github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)


func main() {
	registeredChecks := scanner.GetRegisteredChecks()
	generateChecksFiles(registeredChecks)
}
