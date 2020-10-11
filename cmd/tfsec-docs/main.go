package main

import (
	"fmt"
	"github.com/spf13/cobra"
	_ "github.com/spf13/cobra"
	"os"
	"sort"

	_ "github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

var (
	projectRoot, err = os.Getwd()
	generateWiki     bool
	wikiPath         string
)

type FileContent struct {
	Provider string
	Checks   []scanner.Check
}

func init() {
	defaultWikiPath := fmt.Sprintf("%s/../tfsec.wiki", projectRoot)

	rootCmd.Flags().BoolVar(&generateWiki, "generate-wiki", false, "Generate the basis of wiki entries")
	rootCmd.Flags().StringVar(&wikiPath, "wiki-path", defaultWikiPath, "The path to generate wiki into, defaults to ../tfsec.wiki")
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
	Run: func(cmd *cobra.Command, args []string) {

		checksByProvider := splitChecksIntoProviders()
		var fileContents []*FileContent
		for provider, checks := range checksByProvider {
			fileContents = append(fileContents, &FileContent{
				Provider: provider,
				Checks:   checks,
			})
		}
		generateChecksFiles(fileContents)

		if generateWiki {
			generateWikiPages(fileContents)
		}

	},
}

func splitChecksIntoProviders() map[string][]scanner.Check {
	checks := scanner.GetRegisteredChecks()
	checkMap := make(map[string][]scanner.Check)

	for _, check := range checks {
		provider := string(check.Provider)
		checkMap[provider] = append(checkMap[provider], check)
	}

	for provider := range checkMap {
		sortChecks(checkMap[provider])
	}
	return checkMap
}

func sortChecks(checks []scanner.Check) {
	sort.Slice(checks, func(i, j int) bool {
		return checks[i].Code < checks[j].Code
	})
}
