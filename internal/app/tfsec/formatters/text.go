package formatters

import (
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/result"
)

func FormatText(_ io.Writer, results []result.Result, _ string, options ...FormatterOption) error {

	if len(results) == 0 || len(results) == countPassedResults(results) {
		fmt.Print("\nNo problems detected!\n")
		return nil
	}

	includePassedChecks := false

	for _, option := range options {
		if option == IncludePassed {
			includePassedChecks = true
		}
	}

	var sev string

	fmt.Printf("\n%d potential problems detected:\n\n", len(results)-countPassedResults(results))
	for i, res := range results {

		var link string
		if len(res.Links) > 0 {
			link = res.Links[0]
		}

		fmt.Printf("Check %d\n", i+1)

		if includePassedChecks && res.Passed() {
			sev = "PASSED"
		} else {
			switch res.Severity {
			case severity.Error:
				sev = fmt.Sprintf("%s", res.Severity)
			case severity.Warning:
				sev = fmt.Sprintf("%s", res.Severity)
			default:
				sev = fmt.Sprintf("%s", res.Severity)
			}
		}

		fmt.Printf(`
  [%s][%s] %s
  %s

`, res.RuleID, sev, res.Description, res.Range.String())
		outputCode(res)
		fmt.Printf("  %s\n\n", link)
	}

	return nil

}

// output the lines of code which caused a problem, if available
func outputCode(result result.Result) {
	data, err := ioutil.ReadFile(result.Range.Filename)
	if err != nil {
		return
	}

	lines := append([]string{""}, strings.Split(string(data), "\n")...)

	start := result.Range.StartLine - 3
	if start <= 0 {
		start = 1
	}
	end := result.Range.EndLine + 3
	if end >= len(lines) {
		end = len(lines) - 1
	}

	for lineNo := start; lineNo <= end; lineNo++ {
		fmt.Printf("  % 6d | ", lineNo)
		if lineNo >= result.Range.StartLine && lineNo <= result.Range.EndLine {
			if lineNo == result.Range.StartLine && result.RangeAnnotation != "" {
				fmt.Printf("%s    %s\n", lines[lineNo], result.RangeAnnotation)
			} else {
				fmt.Printf("%s\n", lines[lineNo])
			}
		} else {
			fmt.Printf("%s\n", lines[lineNo])
		}
	}

	fmt.Println("")
}
