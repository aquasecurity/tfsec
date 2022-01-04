package main

import (
	"fmt"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
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
	RunE: func(cmd *cobra.Command, args []string) error {

		fileContents := getSortedFileContents()
		if err := generateExtensionCodeFile(fileContents); err != nil {
			return err
		}

		return generateWebPages(fileContents)
	},
}

func getSortedFileContents() []*FileContent {
	rules := scanner.GetRegisteredRules()

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
			BadExample:  r.BadExample[0],
			GoodExample: r.GoodExample[0],
			Links:       append(r.Links, r.Base.Rule().Links...),
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
