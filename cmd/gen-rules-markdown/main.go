package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

var (
	projectRoot, _ = os.Getwd()
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use: "gen-rules-markdown",
	RunE: func(cmd *cobra.Command, args []string) error {

		fmt.Println("| ID | Provider | Service | Description|\n|-|-|-|-|")

		for _, rule := range scanner.GetRegisteredRules() {
			fmt.Printf("| %s | %s | %s | %s |\n", rule.ID(), rule.Provider, rule.Service, rule.Documentation.Summary)
		}

		return nil
	},
}
