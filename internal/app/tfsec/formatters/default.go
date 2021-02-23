package formatters

import (
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"

	"github.com/tfsec/tfsec/internal/app/tfsec/timer"

	"github.com/liamg/clinch/terminal"
	"github.com/liamg/tml"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func FormatDefault(_ io.Writer, results []scanner.Result, _ string, options ...FormatterOption) error {

	showStatistics := true
	showSuccessOutput := true
	includePassed := false

	for _, option := range options {
		if option == ConciseOutput {
			showStatistics = false
			showSuccessOutput = false
			break
		}

		if option == IncludePassed {
			includePassed = true
		}
	}

	if len(results) == 0 {
		if showStatistics {
			_ = tml.Printf("\n")
			printStatistics(results, includePassed)
		}
		if showSuccessOutput {
			terminal.PrintSuccessf("\nNo problems detected!\n\n")
		}
		return nil
	}

	var severity string

	fmt.Println("")
	for i, result := range results {
		if result.Passed {
			terminal.PrintSuccessf("<underline>Check %d</underline>\n", i+1)
		} else {
			terminal.PrintErrorf("<underline>Check %d</underline>\n", i+1)
		}

		if result.Passed {
			severity = tml.Sprintf("<green>PASSED</green>")
		} else {
			switch result.Severity {
			case scanner.SeverityError:
				severity = tml.Sprintf("<red>%s</red>", result.Severity)
			case scanner.SeverityWarning:
				severity = tml.Sprintf("<yellow>%s</yellow>", result.Severity)
			default:
				severity = tml.Sprintf("<white>%s</white>", result.Severity)
			}
		}

		_ = tml.Printf(`
  <blue>[</blue>%s<blue>]</blue><blue>[</blue>%s<blue>]</blue> %s
  <blue>%s</blue>

`, result.RuleID, severity, result.Description, result.Range.String())
		highlightCode(result)
		tml.Printf("  <blue> %s </blue>\n\n", result.Link)
	}

	// TODO show files processed
	if showStatistics {
		printStatistics(results, includePassed)
	}

	terminal.PrintErrorf("\n%d potential problems detected.\n\n", len(results))

	return nil

}

func printStatistics(results []scanner.Result, includePassed bool) {
	times := timer.Summary()
	for _, operation := range []timer.Operation{
		timer.DiskIO,
		timer.HCLParse,
		timer.Evaluation,
		timer.Check,
	} {
		_ = tml.Printf("  <blue>%-20s</blue> %s\n", operation, times[operation].String())
	}
	_ = tml.Printf("  <blue>%-20s</blue> %d\n", "files loaded", parser.CountFiles())

	if includePassed {
		_ = tml.Printf("  <blue>%-20s</blue> %d\n", "total checks", len(results))
		_ = tml.Printf("  <blue>%-20s</blue> %d\n", "passed checks", getPassedChecks(results))
		_ = tml.Printf("  <blue>%-20s</blue> %d\n", "failed checks", len(results)-getPassedChecks(results))
	}
}

func getPassedChecks(results []scanner.Result) int {
	passed := 0

	for _, result := range results {
		if result.Passed {
			passed++
		}
	}

	return passed
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
				if result.Passed {
					_ = tml.Printf("<bold><green>%s</green>    <blue>%s</blue></bold>\n", lines[lineNo], result.RangeAnnotation)
				} else {
					_ = tml.Printf("<bold><red>%s</red>    <blue>%s</blue></bold>\n", lines[lineNo], result.RangeAnnotation)
				}
			} else {
				if result.Passed {
					_ = tml.Printf("<bold><green>%s</green></bold>\n", lines[lineNo])
				} else {
					_ = tml.Printf("<bold><red>%s</red></bold>\n", lines[lineNo])
				}
			}
		} else {
			_ = tml.Printf("<yellow>%s</yellow>\n", lines[lineNo])
		}
	}

	fmt.Println("")

}
