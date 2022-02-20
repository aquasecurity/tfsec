package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/aquasecurity/tfsec/internal/pkg/executor"
	_ "github.com/aquasecurity/tfsec/internal/pkg/rules"
	"github.com/spf13/cobra"
)

var (
	projectRoot, _ = os.Getwd()
	webPath        string
)

type FileContent struct {
	Provider string
	Checks   []templateObject
}

func init() {
	defaultWebDocsPath := fmt.Sprintf("%s/docs/checks", projectRoot)
	rootCmd.Flags().StringVar(&webPath, "web-path", defaultWebDocsPath, "The path to generate web into, defaults to ./docs/checks")
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
	RunE: func(_ *cobra.Command, _ []string) error {

		fileContents := getSortedFileContents()
		if err := generateWebPages(fileContents); err != nil {
			return err
		}

		return generateIndexPages(fileContents)
	},
}

func getSortedFileContents() []*FileContent {
	rules := executor.GetRegisteredRules()

	checkMap := make(map[string][]templateObject)

	for _, r := range rules {
		provider := string(r.Base.Rule().Provider)
		checkMap[provider] = append(checkMap[provider], templateObject{
			ID:          r.ID(),
			ShortCode:   r.Base.Rule().ShortCode,
			Severity:    strings.ToLower(string(r.Base.Rule().Severity)),
			Service:     r.Base.Rule().Service,
			Provider:    string(r.Base.Rule().Provider),
			Summary:     r.Base.Rule().Summary,
			Explanation: r.Base.Rule().Explanation,
			Impact:      r.Base.Rule().Impact,
			Resolution:  r.Base.Rule().Resolution,
			BadExample:  r.Base.Rule().Terraform.BadExamples[0],
			GoodExample: r.Base.Rule().Terraform.GoodExamples[0],
			Links:       append(r.Base.Rule().Terraform.Links, r.Base.Rule().Links...),
		})
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
	return fileContents
}

func sortChecks(checks []templateObject) {
	sort.Slice(checks, func(i, j int) bool {
		return checks[i].ID < checks[j].ID
	})
}
