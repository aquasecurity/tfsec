package formatters

import (
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/tfsec/tfsec/internal/app/tfsec/metrics"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"

	"github.com/liamg/clinch/terminal"
	"github.com/liamg/tml"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func FormatDefault(_ io.Writer, results []scanner.Result, _ string, options ...FormatterOption) error {

	showStatistics := true
	showSuccessOutput := true
	includePassedChecks := false

	for _, option := range options {
		if option == IncludePassed {
			includePassedChecks = true
		}

		if option == ConciseOutput {
			showStatistics = false
			showSuccessOutput = false
			break
		}
	}

	if len(results) == 0 || len(results) == countPassedResults(results) {
		if showStatistics {
			_ = tml.Printf("\n")
			printStatistics()
		}
		if showSuccessOutput {
			terminal.PrintSuccessf("\nNo problems detected!\n\n")
		}
		return nil
	}

	var severity string

	severityFormat := map[scanner.Severity]string{
		scanner.SeverityInfo:    tml.Sprintf("<white>%s</white>", scanner.SeverityInfo),
		scanner.SeverityWarning: tml.Sprintf("<yellow>%s</yellow>", scanner.SeverityWarning),
		scanner.SeverityError:   tml.Sprintf("<red>%s</red>", scanner.SeverityError),
		"":                      tml.Sprintf("<white>%s</white>", scanner.SeverityInfo),
	}

	fmt.Println("")
	for i, result := range results {
		resultHeader := fmt.Sprintf("<underline>Check %d</underline>\n", i+1)

		if includePassedChecks && result.Passed {
			terminal.PrintSuccessf(resultHeader)
		} else {
			terminal.PrintErrorf(resultHeader)
		}

		if includePassedChecks && result.Passed {
			severity = tml.Sprintf("<green>PASSED</green>")
		} else {
			severity = severityFormat[result.Severity]
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
		printStatistics()
	}

	terminal.PrintErrorf("\n%d potential problems detected.\n\n", len(results)-countPassedResults(results))

	return nil

}

func printStatistics() {
	metrics.Add(metrics.FilesLoaded, parser.CountFiles())

	_ = tml.Printf("  <blue>times</blue>\n  ------------------------------------------\n")
	times := metrics.TimerSummary()
	for _, operation := range []metrics.Operation{
		metrics.DiskIO,
		metrics.HCLParse,
		metrics.Evaluation,
		metrics.Check,
	} {
		_ = tml.Printf("  <blue>%-20s</blue> %s\n", operation, times[operation].String())
	}
	counts := metrics.CountSummary()
	_ = tml.Printf("\n  <blue>counts</blue>\n  ------------------------------------------\n")
	for _, name := range []metrics.Count{
		metrics.FilesLoaded,
		metrics.BlocksLoaded,
		metrics.BlocksEvaluated,
		metrics.ModuleLoadCount,
		metrics.ModuleBlocksLoaded,
	} {
		_ = tml.Printf("  <blue>%-20s</blue> %d\n", name, counts[name])
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
			if result.Passed {
				_ = tml.Printf("<bold><green>%s</green></bold>", lines[lineNo])
			} else if lineNo == result.Range.StartLine && result.RangeAnnotation != "" {
				_ = tml.Printf("<bold><red>%s</red>    <blue>%s</blue></bold>", lines[lineNo], result.RangeAnnotation)
			} else {
				_ = tml.Printf("<bold><red>%s</red></bold>", lines[lineNo])
			}
		} else {
			_ = tml.Printf("<yellow>%s</yellow>", lines[lineNo])
		}

		fmt.Printf("\n")
	}

	fmt.Println("")
}

func countPassedResults(results []scanner.Result) int {
	passed := 0

	for _, result := range results {
		if result.Passed {
			passed++
		}
	}

	return passed
}
