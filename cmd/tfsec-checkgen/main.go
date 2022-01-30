package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/pkg/custom"
	"github.com/aquasecurity/tfsec/internal/pkg/parser"
	"github.com/aquasecurity/tfsec/internal/pkg/scanner"
	"github.com/spf13/cobra"
)

var passTests []string
var failTests []string

func init() {
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(testCheckCmd)
	testCheckCmd.Flags().StringSliceVarP(&passTests, "pass", "p", []string{}, "path to passing test terraform file")
	testCheckCmd.Flags().StringSliceVarP(&failTests, "fail", "f", []string{}, "path to failing test terraform file")
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

func scanTestFile(testFile string) (rules.Results, error) {
	source, err := ioutil.ReadFile(testFile)
	if err != nil {
		return nil, err
	}
	dir, err := ioutil.TempDir(os.TempDir(), "tfsec")
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "test.tf")
	if err := ioutil.WriteFile(path, source, 0600); err != nil {
		return nil, err
	}
	modules, err := parser.New(filepath.Dir(path), parser.OptionStopOnHCLError()).ParseDirectory()
	if err != nil {
		return nil, err
	}
	results, err := scanner.New().Scan(modules)
	return results, err
}

var testCheckCmd = &cobra.Command{
	Use:   "test-check <custom-check-file>",
	Short: "Run test on a custom check against passing/failing tests",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		checkFile, err := custom.LoadCheckFile(args[0])
		if err != nil {
			return err
		}
		custom.ProcessFoundChecks(checkFile)
		for _, passTest := range passTests {
			results, err := scanTestFile(passTest)
			if err != nil {
				return err
			}
			for _, result := range results {
				if result.Rule().LongID()[:6] == "custom" {
					fmt.Printf("failed custom check in expected passing terraform test file: %v\n", passTest)
					fmt.Println(result.Rule().LongID())
					fmt.Println(result.Description())
					return errors.New("test case did not pass")
				}
			}
		}
		for _, failTest := range failTests {
			results, err := scanTestFile(failTest)
			if err != nil {
				return err
			}
			foundFailCheck := false
			for _, result := range results {
				if result.Rule().LongID()[:6] == "custom" {
					foundFailCheck = true
				}
			}
			if !foundFailCheck {
				fmt.Printf("passed custom check in expected failing terraform test file: %v\n", failTest)
				return errors.New("test case did not pass")
			}
		}
		for _, rule := range scanner.GetRegisteredRules() {
			scanner.DeregisterCheckRule(rule)
		}
		return nil
	},
}
