package formatters

import (
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/aquasecurity/tfsec/pkg/result"

	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/metrics"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/parser"

	"github.com/liamg/clinch/terminal"
	"github.com/liamg/tml"
)

var severityFormat = map[severity.Severity]string{
	severity.Low:      tml.Sprintf("<white>%s</white>", severity.Low),
	severity.Medium:   tml.Sprintf("<yellow>%s</yellow>", severity.Medium),
	severity.High:     tml.Sprintf("<red>%s</red>", severity.High),
	severity.Critical: tml.Sprintf("<bold><red>%s</red></bold>", severity.Critical),
	"":                tml.Sprintf("<white>UNKNOWN</white>"),
}

func FormatDefault(_ io.Writer, results []result.Result, _ string, options ...FormatterOption) error {

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

	fmt.Println("")
	for i, res := range results {
		printResult(res, i, includePassedChecks)
	}

	if showStatistics {
		printStatistics()
	}

	terminal.PrintErrorf("\n  %d potential problems detected.\n\n", len(results)-countPassedResults(results))

	return nil

}

func printResult(res result.Result, i int, includePassedChecks bool) {
	resultHeader := fmt.Sprintf("  <underline>Result %d</underline>\n", i+1)
	var severity string
	if includePassedChecks && res.Status == result.Passed {
		terminal.PrintSuccessf(resultHeader)
		severity = tml.Sprintf("<green>PASSED</green>")
	} else {
		terminal.PrintErrorf(resultHeader)
		severity = severityFormat[res.Severity]
	}

	_ = tml.Printf(`
  <blue>[</blue>%s<blue>]</blue><blue>[</blue>%s<blue>]</blue> %s
  <blue>%s</blue>


`, res.RuleID, severity, res.Description, res.Range.String())
	highlightCode(res)
	if res.Impact != "" {
		_ = tml.Printf("  <white>Impact:     </white><blue>%s</blue>\n", res.Impact)
	}
	if res.Resolution != "" {
		_ = tml.Printf("  <white>Resolution: </white><blue>%s</blue>\n", res.Resolution)
	}
	if len(res.Links) > 0 {
		_ = tml.Printf("\n  <white>More Info:</white>")
	}
	for _, link := range res.Links {
		_ = tml.Printf("\n  <blue>- %s </blue>", link)
	}
	fmt.Printf("\n\n")
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
		metrics.IgnoredChecks,
	} {
		_ = tml.Printf("  <blue>%-20s</blue> %d\n", name, counts[name])
	}
}

// highlight the lines of code which caused a problem, if available
func highlightCode(result result.Result) {

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
			if result.Passed() {
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

func countPassedResults(results []result.Result) int {
	passed := 0

	for _, res := range results {
		if res.Passed() {
			passed++
		}
	}

	return passed
}
