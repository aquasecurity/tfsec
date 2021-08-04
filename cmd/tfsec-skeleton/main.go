package main

import (
	"fmt"
	"os"

	"github.com/liamg/clinch/terminal"
	"github.com/spf13/cobra"
)

var forceOverwrite bool

func main() {
	rootCmd.Flags().BoolVarP(&forceOverwrite, "force-overwrite", "f", forceOverwrite, "Overwrite existing checks")
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
	Args: cobra.MaximumNArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {

		var inputs []*Input

		if len(args) == 1 {
			var err error
			inputs, err = generateFromCSV(args[0])
			if err != nil {
				return err
			}

		} else {
			input := &Input{}
			if err := input.gatherInputsInteractively(); err != nil {
				return err
			}
			inputs = []*Input{input}
		}

		var count int
		for _, input := range inputs {
			deref := *input
			if err := writeRuleFromInput(&deref, forceOverwrite); err != nil {
				fmt.Println(err)
				continue
			}
			count++
			fmt.Printf("Added %s-%s-%s...\n", input.Provider, input.Service, input.ShortCode)
		}

		terminal.PrintSuccessf("\nAdded %d new rule(s).\n", count)
		return nil
	},
}
