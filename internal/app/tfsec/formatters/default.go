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

	for _, option := range options {
		if option == ConciseOutput {
			showStatistics = false
			showSuccessOutput = false
			break
		}
	}

	if len(results) == 0 {
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

	fmt.Println("")
	for i, result := range results {
		terminal.PrintErrorf("<underline>Problem %d</underline>\n", i+1)

		switch result.Severity {
		case scanner.SeverityError:
			severity = tml.Sprintf("<red>%s</red>", result.Severity)
		case scanner.SeverityWarning:
			severity = tml.Sprintf("<yellow>%s</yellow>", result.Severity)
		default:
			severity = tml.Sprintf("<white>%s</white>", result.Severity)
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

	terminal.PrintErrorf("\n%d potential problems detected.\n\n", len(results))

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
