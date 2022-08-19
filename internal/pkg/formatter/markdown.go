package formatter

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/defsec/pkg/formatters"
	"github.com/aquasecurity/defsec/pkg/scan"
)

func Markdown() func(b formatters.ConfigurableFormatter, results scan.Results) error {
	return func(b formatters.ConfigurableFormatter, results scan.Results) error {

		filtered := results.GetFailed()
		if b.IncludePassed() {
			filtered = append(filtered, results.GetPassed()...)
		}
		if b.IncludeIgnored() {
			filtered = append(filtered, results.GetIgnored()...)
		}

		if len(filtered) == 0 {
			_, _ = fmt.Fprintf(b.Writer(), "_No problems detected!_")
			return nil
		}

		_, _ = fmt.Fprintln(b.Writer(), "")
		printResultsMarkdown(b, filtered)
		return nil

	}
}

func printResultsTableMarkdown(b formatters.ConfigurableFormatter, title string, results scan.Results) {
	if len(results) == 0 {
		return
	}
	_, _ = fmt.Fprintf(b.Writer(), "## %s: %d issue(s)\n", title, len(results))
	_, _ = fmt.Fprintf(b.Writer(), "| # | ID | Severity | Title | Location | Description |\n")
	_, _ = fmt.Fprintf(b.Writer(), "|---|----|----------|-------|----------|-------------|\n")
	for i, result := range results {
		desc := strings.ReplaceAll(result.Description(), "\n", "<br>")
		location := fmt.Sprintf("%s:%d", b.Path(result, result.Metadata()), result.Range().GetStartLine())
		if result.Range().GetEndLine() > result.Range().GetStartLine() {
			location = fmt.Sprintf("%s-%d", location, result.Range().GetEndLine())
		}
		_, _ = fmt.Fprintf(
			b.Writer(),
			"| %d | `%s` | *%s* | _%s_ | `%s` | %s |\n",
			i+1,
			result.Rule().LongID(),
			result.Severity(),
			result.Rule().Summary,
			location,
			desc,
		)
	}
	_, _ = fmt.Fprint(b.Writer(), "\n")
}

// nolint
func printResultsMarkdown(b formatters.ConfigurableFormatter, results scan.Results) {
	_, _ = fmt.Fprintf(b.Writer(), "# [tfsec] Results\n")
	printResultsTableMarkdown(b, "Failed", results.GetFailed())
	printResultsTableMarkdown(b, "Ignored", results.GetIgnored())
	printResultsTableMarkdown(b, "Passed", results.GetPassed())
}
