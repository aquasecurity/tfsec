package formatters

import (
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"
)

func FormatText(_ io.Writer, results []scanner.Result) error {

	if len(results) == 0 {
		fmt.Print("\nNo problems detected!\n")
	}

	var severity string

	fmt.Printf("\n%d potential problems detected:\n\n", len(results))
	for i, result := range results {
		fmt.Printf("Problem %d\n", i+1)

		switch result.Severity {
		case scanner.SeverityError:
			severity = fmt.Sprintf("%s", result.Severity)
		case scanner.SeverityWarning:
			severity = fmt.Sprintf("%s", result.Severity)
		default:
			severity = fmt.Sprintf("%s", result.Severity)
		}

		fmt.Printf(`
  [%s][%s] %s
  %s

`, result.RuleID, severity, result.Description, result.Range.String())
		outputCode(result)
		fmt.Printf("  See %s for more information.\n\n", result.Link)
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
