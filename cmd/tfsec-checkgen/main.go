package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/pkg/scanners/terraform"

	survey "github.com/AlecAivazis/survey/v2"
	"github.com/aquasecurity/tfsec/internal/pkg/custom"
	"github.com/spf13/cobra"
)

var passTests []string
var failTests []string

func init() {
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(testCheckCmd)
	testCheckCmd.Flags().StringSliceVarP(&passTests, "pass", "p", []string{}, "path to passing test terraform file")
	testCheckCmd.Flags().StringSliceVarP(&failTests, "fail", "f", []string{}, "path to failing test terraform file")
	rootCmd.AddCommand(generateCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		_, _ = fmt.Fprint(os.Stderr, err)
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
			_, _ = fmt.Fprint(os.Stderr, err)
			os.Exit(-1)
		}
		fmt.Println("Config is valid")
		os.Exit(0)
	},
}

func scanTestFile(testFile string) (scan.Results, error) {
	source, err := os.ReadFile(testFile)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(os.TempDir(), "tfsec")
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "test.tf")
	if err := os.WriteFile(path, source, 0600); err != nil {
		return nil, err
	}
	scnr := terraform.New()
	return scnr.ScanFS(context.TODO(), os.DirFS("C:\\"), dir)
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
		return nil
	},
}

var questions = []*survey.Question{
	{
		Name:     "code",
		Prompt:   &survey.Input{Message: "Identifier for the check (e.g. aws001):"},
		Validate: survey.Required,
	},
	{
		Name:   "description",
		Prompt: &survey.Input{Message: "Description text:"},
	},
	{
		Name:   "impact",
		Prompt: &survey.Input{Message: "Potential impact of the vulnerability:"},
	},
	{
		Name:   "resolution",
		Prompt: &survey.Input{Message: "Resolution hint text:"},
	},
	{
		Name: "requiredTypes",
		Prompt: &survey.MultiSelect{
			Message: "Target block type(s):",
			Options: []string{"resource", "data", "module", "variable"},
		},
		Validate: survey.Required,
	},
	{
		Name:     "requiredLabelsRaw",
		Prompt:   &survey.Multiline{Message: "Target block label(s) (one per line) (e.g. aws_instance):"},
		Validate: survey.Required,
	},
	{
		Name: "severity",
		Prompt: &survey.Select{
			Message: "Level of severity:",
			Options: []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "ERROR", "WARNING", "INFO"},
		},
		Validate: survey.Required,
	},
	{
		Name:   "errorMessage",
		Prompt: &survey.Input{Message: "Error message text:"},
	},
	{
		Name:   "relatedLinksRaw",
		Prompt: &survey.Multiline{Message: "Related link(s) (one per line):"},
	},
}

var fileQuestions = []*survey.Question{
	{
		Name:   "filepath",
		Prompt: &survey.Input{Message: "Relative path to save the custom check (must end in _tfchecks.[json/yaml]):"},
		Validate: survey.ComposeValidators(
			survey.Required,
			func(val interface{}) error {
				if strings.HasSuffix(fmt.Sprintf("%v", val), "_tfchecks.json") || strings.HasSuffix(fmt.Sprintf("%v", val), "_tfchecks.yaml") {
					return nil
				} else {
					return errors.New("must end in _tfchecks.json or _tfchecks.yaml")
				}
			},
		),
	},
}

type GenAns struct {
	Code              string
	Description       string
	Impact            string
	Resolution        string
	RequiredTypes     []string
	RequiredLabels    []string
	RequiredLabelsRaw string
	Severity          string
	ErrorMessage      string
	RelatedLinks      []string
	RelatedLinksRaw   string
}

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a custom check starter template",
	Long:  "CLI util to generate a custom check starter template",
	Run: func(cmd *cobra.Command, args []string) {
		addCheckAns := true
		allAns := []GenAns{}

		for addCheckAns {
			ans := GenAns{}
			if err := survey.Ask(questions, &ans); err != nil {
				fmt.Println(err.Error())
				os.Exit(1)
			}

			ans.RequiredLabels = strings.Split(fmt.Sprintf("%v", ans.RequiredLabelsRaw), "\n")
			ans.RelatedLinks = strings.Split(fmt.Sprintf("%v", ans.RelatedLinksRaw), "\n")

			allAns = append(allAns, ans)
			if err := survey.AskOne(&survey.Confirm{Message: "Add another check to the file?:"}, &addCheckAns); err != nil {
				fmt.Println(err.Error())
				os.Exit(1)
			}
		}

		fileAns := struct {
			Filepath string
		}{}
		if err := survey.Ask(fileQuestions, &fileAns); err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		output := ""

		if strings.HasSuffix(fileAns.Filepath, ".json") {
			for _, ans := range allAns {
				var requiredTypes = linesToJSONArrayString(ans.RequiredTypes, 8)
				var requiredLabels = linesToJSONArrayString(ans.RequiredLabels, 8)
				var relatedLinks = linesToJSONArrayString(ans.RelatedLinks, 8)

				output += fmt.Sprintf(`
    {
      "code": "%s",
      "description": "%s",
      "impact": "%s",
      "resolution": "%s",
      "requiredTypes": [
%s
      ],
      "requiredLabels": [
%s
      ],
      "severity": "%s",
      "matchSpec": {
        "name": "tags",
        "action": "contains",
        "value": "example"
      },
      "errorMessage": "%s",
      "relatedLinks": [
%s
      ]
    },`,
					ans.Code,
					ans.Description,
					ans.Impact,
					ans.Resolution,
					requiredTypes,
					requiredLabels,
					ans.Severity,
					ans.ErrorMessage,
					relatedLinks)
			}
			output = fmt.Sprintf(`{
  "checks": [%s
  ]
}
`, output[:len(output)-1])
		} else {
			for _, ans := range allAns {
				var requiredTypes = linesToYAMLArrayString(ans.RequiredTypes, 2)
				var requiredLabels = linesToYAMLArrayString(ans.RequiredLabels, 2)
				var relatedLinks = linesToYAMLArrayString(ans.RelatedLinks, 2)
				output += fmt.Sprintf(`
- code: %s
  description: %s
  impact: %s
  resolution: %s
  requiredTypes:
%s
  requiredLabels:
%s
  severity: %s
  matchSpec:
    name: tags
    action: contains
    value: CostCentre
  errorMessage: %s
  relatedLinks:
%s`,
					ans.Code,
					ans.Description,
					ans.Impact,
					ans.Resolution,
					requiredTypes,
					requiredLabels,
					ans.Severity,
					ans.ErrorMessage,
					relatedLinks)
			}
			output = fmt.Sprintf(`---
checks:%s
`, output[:len(output)-1])
		}

		err := os.WriteFile(fileAns.Filepath, []byte(output), 0600)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
	},
}

func linesToJSONArrayString(lines []string, padCount int) string {
	if len(lines) == 0 {
		return ""
	}
	var requiredTypes = ""
	for _, line := range lines {
		requiredTypes += strings.Repeat(" ", padCount) + fmt.Sprintf("\"%s\",\n", strings.TrimSpace(line))
	}
	return requiredTypes[:len(requiredTypes)-2]
}

func linesToYAMLArrayString(lines []string, padCount int) string {
	if len(lines) == 0 {
		return ""
	}
	var requiredTypes = ""
	for _, line := range lines {
		requiredTypes += strings.Repeat(" ", padCount) + fmt.Sprintf("- %s\n", strings.TrimSpace(line))
	}
	return requiredTypes[:len(requiredTypes)-1]
}
