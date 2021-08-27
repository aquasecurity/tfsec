package formatters

import (
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/metrics"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/parser"

	"github.com/liamg/clinch/terminal"
	"github.com/liamg/gifwrap/pkg/ascii"
	"github.com/liamg/tml"
)

var severityFormat map[severity.Severity]string

func FormatDefault(_ io.Writer, results rules.Results, _ string, options ...FormatterOption) error {
	if severityFormat == nil { // has to be created at call-time so --no-color is taken into account
		severityFormat = map[severity.Severity]string{
			severity.Low:      tml.Sprintf("<white>%s</white>", severity.Low),
			severity.Medium:   tml.Sprintf("<yellow>%s</yellow>", severity.Medium),
			severity.High:     tml.Sprintf("<red>%s</red>", severity.High),
			severity.Critical: tml.Sprintf("<bold><red>%s</red></bold>", severity.Critical),
			"":                tml.Sprintf("<white>UNKNOWN</white>"),
		}
	}
	showStatistics := true
	showSuccessOutput := true
	includePassedChecks := false

	var showGif bool

	for _, option := range options {
		switch option {
		case IncludePassed:
			includePassedChecks = true
		case ConciseOutput:
			showStatistics = false
			showSuccessOutput = false
		case PassingGif:
			showGif = true
		}
	}

	if len(results) == 0 || len(results) == countPassedResults(results) {
		if showGif {
			if renderer, err := ascii.FromURL("https://media.giphy.com/media/kyLYXonQYYfwYDIeZl/source.gif"); err == nil {
				renderer.SetFill(true)
				renderer.PlayOnce()
			}
		}
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

func printResult(res rules.Result, i int, includePassedChecks bool) {
	resultHeader := fmt.Sprintf("  <underline>Result %d</underline>\n", i+1)
	var severity string
	if includePassedChecks && res.Status() == rules.StatusPassed {
		terminal.PrintSuccessf(resultHeader)
		severity = tml.Sprintf("<green>PASSED</green>")
	} else {
		terminal.PrintErrorf(resultHeader)
		severity = severityFormat[res.Rule().Severity]
	}

	_ = tml.Printf(`
<blue>[</blue>%s<blue>]</blue><blue>[</blue>%s<blue>]</blue> <yellow>%s</yellow>: %s
  <blue>%s</blue>


`, res.Rule().LongID(), severity, res.Reference().(*block.Reference).HumanReadable(), res.Description(), res.Metadata().Range().String())
	highlightCode(res)

	if longID := scanner.FindLegacyID(res.Rule().LongID()); longID != "" {
		_ = tml.Printf("  <white>Legacy ID:  </white><blue>%s</blue>\n", longID)
	}
	if res.Rule().Impact != "" {
		_ = tml.Printf("  <white>Impact:     </white><blue>%s</blue>\n", res.Rule().Impact)
	}
	if res.Rule().Resolution != "" {
		_ = tml.Printf("  <white>Resolution: </white><blue>%s</blue>\n", res.Rule().Resolution)
	}
	if len(res.Rule().Links) > 0 {
		_ = tml.Printf("\n  <white>More Info:</white>")
	}
	for _, link := range res.Rule().Links {
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
		metrics.InfraChecks,
		metrics.HCLChecks,
		metrics.Adaptation,
	} {
		_ = tml.Printf("  <blue>%-20s</blue> %s\n", operation, times[operation].String())
	}

	_ = tml.Printf("\n  <blue>counts</blue>\n  ------------------------------------------\n")
	counts := metrics.CountSummary()
	for _, name := range []metrics.Count{
		metrics.FilesLoaded,
		metrics.BlocksLoaded,
		metrics.ModuleLoadCount,
	} {
		_ = tml.Printf("  <blue>%-20s</blue> %d\n", name, counts[name])
	}

	_ = tml.Printf("\n  <blue>results</blue>\n  ------------------------------------------\n")
	for _, sev := range []severity.Severity{
		severity.Critical,
		severity.High,
		severity.Medium,
		severity.Low,
	} {
		count := metrics.CountSeverity(sev)
		_ = tml.Printf("  <blue>%-20s</blue> %d\n", strings.ToLower(string(sev)), count)
	}
	_ = tml.Printf("  <blue>%-20s</blue> %d\n", "ignored", counts[metrics.IgnoredChecks])
}

// highlight the lines of code which caused a problem, if available
func highlightCode(result rules.Result) {

	data, err := ioutil.ReadFile(result.Metadata().Range().GetFilename())
	if err != nil {
		return
	}

	lines := append([]string{""}, strings.Split(string(data), "\n")...)

	start := result.Metadata().Range().GetStartLine() - 3
	if start <= 0 {
		start = 1
	}
	end := result.Metadata().Range().GetEndLine() + 3
	if end >= len(lines) {
		end = len(lines) - 1
	}

	for lineNo := start; lineNo <= end; lineNo++ {
		_ = tml.Printf("  <blue>% 6d</blue> | ", lineNo)
		if lineNo >= result.Metadata().Range().GetStartLine() && lineNo <= result.Metadata().Range().GetEndLine() {
			if result.Status() == rules.StatusPassed {
				_ = tml.Printf("<bold><green>%s</green></bold>", lines[lineNo])
			} else if lineNo == result.Metadata().Range().GetStartLine() && result.Annotation() != "" {
				_ = tml.Printf("<bold><red>%s</red>    <blue>%s</blue></bold>", lines[lineNo], result.Annotation())
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

func countPassedResults(results rules.Results) int {
	passed := 0

	for _, res := range results {
		if res.Status() == rules.StatusPassed {
			passed++
		}
	}

	return passed
}
