package formatters

import (
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/aquasecurity/defsec/types"
)

func FormatText(writer io.Writer, results []types.Result, _ string, options ...FormatterOption) error {

	if len(results) == 0 || len(results) == countPassedResults(results) {
		fmt.Fprint(writer, "\nNo problems detected!\n")
		return nil
	}

	includePassedChecks := false

	for _, option := range options {
		if option == IncludePassed {
			includePassedChecks = true
		}
	}

	var sev string

	fmt.Fprintf(writer, "\n%d potential problems detected:\n\n", len(results)-countPassedResults(results))
	for i, res := range results {

		var link string
		if len(res.Links) > 0 {
			link = res.Links[0]
		}

		fmt.Fprintf(writer, "Check %d\n", i+1)

		if includePassedChecks && res.Passed() {
			sev = "PASSED"
		} else {
			sev = string(res.Severity)
		}

		fmt.Fprintf(writer, `
  [%s][%s] %s
  %s

`, res.RuleID, sev, res.Description, res.Range().String())
		outputCode(*res, writer)
		fmt.Fprintf(writer, "  %s\n\n", link)
	}

	return nil

}

// output the lines of code which caused a problem, if available
func outputCode(result types.Result, writer io.Writer) {
	data, err := ioutil.ReadFile(result.Range().GetFilename())
	if err != nil {
		return
	}

	lines := append([]string{""}, strings.Split(string(data), "\n")...)

	start := result.Range().GetStartLine() - 3
	if start <= 0 {
		start = 1
	}
	end := result.Range().GetEndLine() + 3
	if end >= len(lines) {
		end = len(lines) - 1
	}

	for lineNo := start; lineNo <= end; lineNo++ {
		fmt.Fprintf(writer, "  % 6d | ", lineNo)
		if lineNo >= result.Range().GetStartLine() && lineNo <= result.Range().GetEndLine() {
			if lineNo == result.Range().GetStartLine() && result.RangeAnnotation != "" {
				fmt.Fprintf(writer, "%s    %s\n", lines[lineNo], result.RangeAnnotation)
			} else {
				fmt.Fprintf(writer, "%s\n", lines[lineNo])
			}
		} else {
			fmt.Fprintf(writer, "%s\n", lines[lineNo])
		}
	}

	fmt.Fprintln(writer, "")
}
