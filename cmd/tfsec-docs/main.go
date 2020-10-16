package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"

	_ "github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

var (
	projectRoot, _ = os.Getwd()
	webPath        string
)

type FileContent struct {
	Provider string
	Checks   []scanner.Check
}

func init() {
	defaultWebDocsPath := fmt.Sprintf("%s/docs-website", projectRoot)
	rootCmd.Flags().StringVar(&webPath, "web-path", defaultWebDocsPath, "The path to generate web into, defaults to ./docs-website")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "tfsec-docs",
	Short: "tfsec-docs generates documentation for the checks in tfsec",
	Long:  `tfsec-docs generates the content for the root README and also can generate the missing base pages for the wiki`,
	RunE: func(cmd *cobra.Command, args []string) error {

		fileContents := getSortedFileContents()
		if err := generateChecksFiles(fileContents); err != nil {
			return err
		}

		return generateWebPages(fileContents)
	},
}

func getSortedFileContents() []*FileContent {
	checks := scanner.GetRegisteredChecks()
	checkMap := make(map[string][]scanner.Check)

	for _, check := range checks {
		provider := string(check.Provider)
		checkMap[provider] = append(checkMap[provider], check)
	}

	var fileContents []*FileContent
	for provider := range checkMap {
		checks := checkMap[provider]
		sortChecks(checks)
		fileContents = append(fileContents, &FileContent{
			Provider: provider,
			Checks:   checks,
		})
	}
	sortFileContentsByProvider(fileContents)
	return fileContents
}

func sortChecks(checks []scanner.Check) {
	sort.Slice(checks, func(i, j int) bool {
		return checks[i].Code < checks[j].Code
	})
}

func sortFileContentsByProvider(fileContents []*FileContent) {
	sort.Slice(fileContents, func(i, j int) bool {
		return fileContents[i].Provider < fileContents[j].Provider
	})
}
