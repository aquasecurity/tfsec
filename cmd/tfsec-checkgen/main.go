package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/tfsec/tfsec/internal/app/tfsec/custom"
	"os"
)

func init() {
	rootCmd.AddCommand(validateCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "tfsec-checkgen",
	Short: "tfsec-checkgen is a tfsec tool for generating and validating custom check files.",
	Long: `tfsec is a simple tool for generating and validating custom checks file.
Custom checks are defined as json and stored in the .tfsec directory of the folder being checked.
`,
}

var validateCmd = &cobra.Command{
	Use:   "validate [checkfile]",
	Short: "Validate a custom checks file to ensure values are correct",
	Long:  "Confirm that all of the attributes of the supplied custom checks file are valid and can be used",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		err := custom.Validate(args[0])
		if err != nil {
			fmt.Fprint(os.Stderr, err)
			os.Exit(-1)
		}
		fmt.Println("Config is valid")
		os.Exit(0)
	},
}
