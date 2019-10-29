package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/liamg/clinch/terminal"
	"github.com/liamg/tfsec/internal/app/tfsec/parser"
	"github.com/liamg/tfsec/internal/app/tfsec/scanner"
	"github.com/liamg/tfsec/version"
	"github.com/spf13/cobra"
)

var showVersion = false

func init() {
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", showVersion, "Show version information and exit")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "tfsec [directory]",
	Short: "tfsec is a terraform security scanner",
	Long:  `tfsec is a simple tool to detect potential security vulnerabilities in your terraformed infrastructure.`,
	Run: func(cmd *cobra.Command, args []string) {

		if showVersion {
			fmt.Println(version.Version)
			os.Exit(0)
		}

		var dir string
		var err error
		if len(args) == 1 {
			dir, err = filepath.Abs(args[0])
		} else {
			dir, err = os.Getwd()
		}
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		blocks, ctx, err := parser.New().ParseDirectory(dir)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		results := scanner.New().Scan(blocks, ctx)
		if len(results) == 0 {
			terminal.PrintSuccessf("No problems detected!\n")
			os.Exit(0)
		}

		terminal.PrintErrorf("%d problems detected:\n\n", len(results))
		for i, result := range results {
			terminal.PrintErrorf("Problem %d", i+1)
			fmt.Printf(`
  %s
  %s

`, result.Range.String(), result.Description)
		}

		os.Exit(1)
	},
}
