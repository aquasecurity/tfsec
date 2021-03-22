package formatters

import (
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func FormatText(_ io.Writer, results []scanner.Result, _ string, options ...FormatterOption) error {

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

	var severity string

	fmt.Printf("\n%d potential problems detected:\n\n", len(results)-countPassedResults(results))
	for i, result := range results {
		fmt.Printf("Check %d\n", i+1)

		if includePassedChecks && result.Passed {
			severity = "PASSED"
		} else {
			switch result.Severity {
			case scanner.SeverityError:
				severity = fmt.Sprintf("%s", result.Severity)
			case scanner.SeverityWarning:
				severity = fmt.Sprintf("%s", result.Severity)
			default:
				severity = fmt.Sprintf("%s", result.Severity)
			}
		}

		fmt.Printf(`
  [%s][%s] %s
  %s

`, result.RuleID, severity, result.Description, result.Range.String())
		outputCode(result)
		fmt.Printf("  %s\n\n", result.Link)
	}

	return nil

}

// output the lines of code which caused a problem, if available
func outputCode(result scanner.Result) {
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
