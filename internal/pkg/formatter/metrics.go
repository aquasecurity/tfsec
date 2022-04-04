package formatter

import (
	"fmt"
	"io"
	"strings"

	"github.com/liamg/tml"

	scanner "github.com/aquasecurity/defsec/pkg/scanners/terraform"
)

func printMetrics(w io.Writer, metrics scanner.Metrics) {

	printTitle(w, "timings")
	printValue(w, "disk i/o", metrics.Parser.Timings.DiskIODuration.String())
	printValue(w, "parsing", metrics.Parser.Timings.ParseDuration.String())
	printValue(w, "adaptation", metrics.Executor.Timings.Adaptation.String())
	printValue(w, "checks", metrics.Executor.Timings.RunningChecks.String())
	printValue(w, "total", metrics.Timings.Total.String())
	_, _ = fmt.Fprintf(w, "\n")

	printTitle(w, "counts")
	printValue(w, "modules downloaded", fmt.Sprintf("%d", metrics.Parser.Counts.ModuleDownloads))
	printValue(w, "modules processed", fmt.Sprintf("%d", metrics.Parser.Counts.Modules))
	printValue(w, "blocks processed", fmt.Sprintf("%d", metrics.Parser.Counts.Blocks))
	printValue(w, "files read", fmt.Sprintf("%d", metrics.Parser.Counts.Files))
	_, _ = fmt.Fprintf(w, "\n")

	printTitle(w, "results")
	printValue(w, "passed", fmt.Sprintf("%d", metrics.Executor.Counts.Passed))
	printValue(w, "ignored", fmt.Sprintf("%d", metrics.Executor.Counts.Ignored))
	printValue(w, "critical", fmt.Sprintf("%d", metrics.Executor.Counts.Critical))
	printValue(w, "high", fmt.Sprintf("%d", metrics.Executor.Counts.High))
	printValue(w, "medium", fmt.Sprintf("%d", metrics.Executor.Counts.Medium))
	printValue(w, "low", fmt.Sprintf("%d", metrics.Executor.Counts.Low))
	_, _ = fmt.Fprintf(w, "\n")
}

func printTitle(w io.Writer, title string) {
	_ = tml.Fprintf(w, "  <bold>%s</bold>\n  %s\n", title, strings.Repeat("─", 42))
}

func printValue(w io.Writer, key, val string) {
	_ = tml.Fprintf(w, "  <dim>%-20s</dim> %s\n", key, val)
}
