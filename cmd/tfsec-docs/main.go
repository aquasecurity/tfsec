package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/spf13/cobra"

	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

var (
	projectRoot, _ = os.Getwd()
	webPath        string
)

type FileContent struct {
	Provider string
	Checks   []rule.Rule
}

func init() {
	defaultWebDocsPath := fmt.Sprintf("%s/checkdocs", projectRoot)
	rootCmd.Flags().StringVar(&webPath, "web-path", defaultWebDocsPath, "The path to generate web into, defaults to ./checkdocs")
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
	rules := scanner.GetRegisteredRules()

	checkMap := make(map[string][]rule.Rule)

	for _, r := range rules {
		provider := string(r.Provider)
		checkMap[provider] = append(checkMap[provider], r)
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
	generateNavIndexFile(fileContents)
	return fileContents
}

func sortChecks(checks []rule.Rule) {
	sort.Slice(checks, func(i, j int) bool {
		return checks[i].ID() < checks[j].ID()
	})
}
