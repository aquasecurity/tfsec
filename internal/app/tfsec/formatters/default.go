package formatters

import (
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/liamg/clinch/terminal"
	"github.com/liamg/tfsec/internal/app/tfsec/scanner"
	"github.com/liamg/tml"
)

func FormatDefault(results []scanner.Result) {

	if len(results) == 0 {
		terminal.PrintSuccessf("\nNo problems detected!\n")
	}

	terminal.PrintErrorf("\n%d potential problems detected:\n\n", len(results))
	for i, result := range results {
		terminal.PrintErrorf("<underline>Problem %d</underline>\n", i+1)
		_ = tml.Printf(`
  <blue>[</blue>%s<blue>]</blue> %s
  <blue>%s</blue>

`, result.Code, result.Description, result.Range.String())
		highlightCode(result)
	}

}

// highlight the lines of code which caused a problem, if available
func highlightCode(result scanner.Result) {

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
		_ = tml.Printf("  <blue>% 6d</blue> | ", lineNo)
		if lineNo >= result.Range.StartLine && lineNo <= result.Range.EndLine {
			if lineNo == result.Range.StartLine && result.RangeAnnotation != "" {
				_ = tml.Printf("<bold><red>%s</red>    <blue>%s</blue></bold>\n", lines[lineNo], result.RangeAnnotation)
			} else {
				_ = tml.Printf("<bold><red>%s</red></bold>\n", lines[lineNo])
			}
		} else {
			_ = tml.Printf("<yellow>%s</yellow>\n", lines[lineNo])
		}
	}

	fmt.Println("")

}
