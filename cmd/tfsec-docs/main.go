package main

import (
	_ "github.com/spf13/cobra"
	_ "github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
	"sort"
)


func main() {
	registeredChecks := scanner.GetRegisteredChecks()
	sort.Slice(registeredChecks, func(i, j int) bool {
		return registeredChecks[i].Code < registeredChecks[j].Code
	})
	generateChecksFile(registeredChecks)
}
