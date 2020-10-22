package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		_, _ = fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "tfsec-skeleton",
	Short: "tfsec-skeleton is a tfsec tool for generating code files for checks.",
	Long: `tfsec-skeleton is a simple tool for generating check code files at a corresponding test file.
`,
	Run: func(cmd *cobra.Command, args []string) {
		err := generateCheckBody()
		if err != nil {
			panic(err)
		}
	},
}
