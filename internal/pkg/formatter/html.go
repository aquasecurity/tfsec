package formatter

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aquasecurity/defsec/pkg/severity"

	"github.com/aquasecurity/defsec/pkg/formatters"
	"github.com/aquasecurity/defsec/pkg/scan"
)

func HTML() func(b formatters.ConfigurableFormatter, results scan.Results) error {
	return func(b formatters.ConfigurableFormatter, results scan.Results) error {

		// html header
		_, _ = fmt.Fprintln(b.Writer(), `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>tfsec - Results</title>
    <style>
      * { background-color: #222222; color: #ffffff; }
      body { font-size: 20px; } 
      .severity { color: #777777; }
      .CRITICAL { font-weight: bold; color: #cc1111;}
      .HIGH { color: #ff0000; }
      .MEDIUM { color: #ff6600; }
      .LOW { color: #ffff00; }
      table { border: 1px solid #555555; }
      thead tr th {
        background-color: #555555;
        padding: 5px 10px 5px 10px;
      }
      tbody tr td { padding: 5px 10px 5px 10px; }
    </style>
  </head>
  <body>`)

		filtered := results.GetFailed()
		if b.IncludePassed() {
			filtered = append(filtered, results.GetPassed()...)
		}
		if b.IncludeIgnored() {
			filtered = append(filtered, results.GetIgnored()...)
		}

		if len(filtered) == 0 {
			_, _ = fmt.Fprintf(b.Writer(), "<i>No problems detected!</i>")
			return nil
		}

		printResultsHTML(b, filtered)

		// html footer
		_, _ = fmt.Fprintln(b.Writer(), `  </body>
</html>`)

		return nil

	}
}

var severityScores = map[severity.Severity]uint8{
	severity.None:     0,
	severity.Low:      1,
	severity.Medium:   2,
	severity.High:     3,
	severity.Critical: 4,
}

func printResultsTableHTML(b formatters.ConfigurableFormatter, title string, results scan.Results) {
	if len(results) == 0 {
		return
	}

	sort.Slice(results, func(i, j int) bool {
		scoreI := severityScores[results[i].Severity()]
		scoreJ := severityScores[results[j].Severity()]
		if scoreI == scoreJ {
			return results[i].Rule().LongID() < results[j].Rule().LongID()
		}
		return scoreI > scoreJ
	})

	_, _ = fmt.Fprintf(b.Writer(), "    <h2>%s: %d issue(s)</h2>\n", title, len(results))
	_, _ = fmt.Fprintf(b.Writer(), `    <table class="pure-table">
      <thead>
        <tr><th> # </th><th> ID </th><th> Severity </th><th> Title </th><th> Location </th><th> Description </th></tr>
      </thead>
      <tbody>
`)
	for i, result := range results {
		desc := strings.ReplaceAll(result.Description(), "\n", "<br>")
		location := fmt.Sprintf("%s:%d", b.Path(result, result.Metadata()), result.Range().GetStartLine())
		if result.Range().GetEndLine() > result.Range().GetStartLine() {
			location = fmt.Sprintf("%s-%d", location, result.Range().GetEndLine())
		}
		var href string
		if len(result.Rule().Links) > 0 {
			href = result.Rule().Links[0]
		}
		_, _ = fmt.Fprintf(
			b.Writer(),
			`        <tr>
          <td>%d</td>
          <td><a target="_blank" rel="noopener" href="%s">%s</a></td>
          <td class="severity %s">%s</td>
          <td><i>%s</i></td>
          <td><code>%s</code></td>
          <td>%s</td>
        </tr>
`,
			i+1,
			href,
			result.Rule().LongID(),
			result.Severity(),
			result.Severity(),
			result.Rule().Summary,
			location,
			desc,
		)
	}
	_, _ = fmt.Fprint(b.Writer(), `
      </tbody>
    </table>
`)
}

// nolint
func printResultsHTML(b formatters.ConfigurableFormatter, results scan.Results) {
	_, _ = fmt.Fprintf(b.Writer(), "    <h1>[tfsec] Results</h1>\n")
	printResultsTableHTML(b, "Failed", results.GetFailed())
	printResultsTableHTML(b, "Ignored", results.GetIgnored())
	printResultsTableHTML(b, "Passed", results.GetPassed())
}
