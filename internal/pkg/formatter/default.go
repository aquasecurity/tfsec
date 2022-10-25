package formatter

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/defsec/pkg/scan"
	scanner "github.com/aquasecurity/defsec/pkg/scanners/terraform"

	"github.com/aquasecurity/defsec/pkg/formatters"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/liamg/clinch/terminal"
	"github.com/liamg/tml"
)

var severityFormat map[severity.Severity]string

func DefaultWithMetrics(metrics scanner.Metrics, conciseOutput bool, codeTheme string, withColours bool, noCode bool) func(b formatters.ConfigurableFormatter, results scan.Results) error {
	return func(b formatters.ConfigurableFormatter, results scan.Results) error {

		// turn on no-code if consise output required
		if conciseOutput {
			noCode = true
		}

		// we initialise the map here so we respect the colour-ignore options
		severityFormat = map[severity.Severity]string{
			severity.Low:      tml.Sprintf("<white>%s</white>", severity.Low),
			severity.Medium:   tml.Sprintf("<yellow>%s</yellow>", severity.Medium),
			severity.High:     tml.Sprintf("<red>%s</red>", severity.High),
			severity.Critical: tml.Sprintf("<bold><red>%s</red></bold>", severity.Critical),
			"":                tml.Sprintf("<white> UNKNOWN</white>"),
		}

		filtered := results.GetFailed()
		if b.IncludePassed() {
			filtered = append(filtered, results.GetPassed()...)
		}
		if b.IncludeIgnored() {
			filtered = append(filtered, results.GetIgnored()...)
		}

		if len(filtered) == 0 {
			if !conciseOutput {
				printMetrics(b.Writer(), metrics)
			}

			_ = tml.Fprintf(b.Writer(), "\n<green><bold>No problems detected!\n\n")
			return nil
		}

		groups, err := b.GroupResults(filtered)
		if err != nil {
			return err
		}

		_, _ = fmt.Fprintln(b.Writer(), "")
		for _, group := range groups {
			printResult(b, group, codeTheme, withColours, noCode)
		}

		if !conciseOutput {
			printMetrics(b.Writer(), metrics)
		}

		var passInfo string
		if passCount := len(results.GetPassed()); passCount > 0 {
			passInfo = fmt.Sprintf("%d passed, ", passCount)
		}
		var ignoreInfo string
		if ignoreCount := len(results.GetIgnored()); ignoreCount > 0 {
			ignoreInfo = fmt.Sprintf("%d ignored, ", ignoreCount)
		}
		_ = tml.Fprintf(b.Writer(), "  <red><bold>%s%s%d potential problem(s) detected.\n\n", passInfo, ignoreInfo, len(results.GetFailed()))

		return nil

	}
}

func getStatusOrSeverity(status scan.Status, severity severity.Severity) string {
	switch status {
	case scan.StatusPassed:
		return tml.Sprintf("<green>PASSED</green>")
	case scan.StatusIgnored:
		return tml.Sprintf("<yellow>IGNORED</yellow> (") + severityFormat[severity] + ")"
	default:
		return severityFormat[severity]
	}
}

type simpleLocation struct {
	filename   string
	lineInfo   string
	moduleName string
}

func getOccurrences(first scan.Result, baseDir string) []simpleLocation {
	var via []simpleLocation
	m := first.Metadata()
	mod := &m
	lastFilename := m.Range().GetFilename()
	for {
		mod = mod.Parent()
		if mod == nil {
			break
		}
		parentRange := mod.Range()
		parentFilename := parentRange.GetFilename()
		if parentFilename == lastFilename {
			continue
		}
		lastFilename = parentFilename
		if parentRange.GetSourcePrefix() == "" || strings.HasPrefix(parentRange.GetSourcePrefix(), ".") {
			if parentRelative, err := filepath.Rel(baseDir, parentFilename); err == nil && !strings.Contains(parentRelative, "..") {
				parentLineInfo := fmt.Sprintf(":%d-%d", parentRange.GetStartLine(), parentRange.GetEndLine())
				if !parentRange.IsMultiLine() {
					parentLineInfo = fmt.Sprintf(":%d", parentRange.GetStartLine())
				}
				via = append(via, simpleLocation{
					filename:   parentRelative,
					lineInfo:   parentLineInfo,
					moduleName: mod.Reference(),
				})
			}
		} else {
			parentLineInfo := fmt.Sprintf(":%d-%d", parentRange.GetStartLine(), parentRange.GetEndLine())
			if !parentRange.IsMultiLine() {
				parentLineInfo = fmt.Sprintf(":%d", parentRange.GetStartLine())
			}
			via = append(via, simpleLocation{
				filename:   parentRange.GetFilename(),
				lineInfo:   parentLineInfo,
				moduleName: mod.Reference(),
			})
		}

	}
	return via
}

// nolint
func printResult(b formatters.ConfigurableFormatter, group formatters.GroupedResult, theme string, withColours bool,
	noCode bool) {

	first := group.Results()[0]

	isRego := first.Rule().RegoPackage != ""
	severityFormatted := getStatusOrSeverity(first.Status(), first.Severity())

	width, _ := terminal.Size()
	if width <= 0 {
		width = 80
	}

	w := b.Writer()

	numPrefix := "Result"
	var groupingInfo string
	if group.Len() > 1 {
		numPrefix = "Results"
		groupingInfo = fmt.Sprintf("(%d similar results)", group.Len())
	}

	_ = tml.Fprintf(
		w,
		"<italic>%s %s</italic> %s <bold>%s</bold> <dim>%s</dim>\n",
		numPrefix,
		group.String(),
		severityFormatted,
		first.Description(),
		groupingInfo,
	)

	innerRange := first.Range()
	lineInfo := fmt.Sprintf(":%d-%d", innerRange.GetStartLine(), innerRange.GetEndLine())
	if !innerRange.IsMultiLine() {
		lineInfo = fmt.Sprintf(":%d", innerRange.GetStartLine())
	}

	via := getOccurrences(first, b.BaseDir())
	filename := b.Path(first, first.Metadata())

	_ = tml.Fprintf(
		w,
		"<darkgrey>%s\n",
		strings.Repeat("─", width),
	)

	if first.Metadata().Range().GetStartLine() == 0 {
		if filename != "" {
			_ = tml.Fprintf(
				w,
				"<darkgrey>%s</darkgrey>\n  <italic>%s",
				strings.Repeat("─", width),
				filename,
			)
		}
	} else {
		_ = tml.Fprintf(
			w,
			"  <italic>%s<dim>%s\n",
			filename,
			lineInfo,
		)
		for i, v := range via {
			_ = tml.Fprintf(
				w,
				" %s<dim>via </dim><italic>%s<dim>%s (%s)\n",
				strings.Repeat(" ", i+2),
				v.filename,
				v.lineInfo,
				v.moduleName,
			)
		}

		_ = tml.Fprintf(
			w,
			"<darkgrey>%s</darkgrey>\n",
			strings.Repeat("─", width),
		)
		if !noCode {
			if err := highlightCode(b, first, theme, withColours); err != nil {
				_, _ = fmt.Fprintf(w, tml.Sprintf("  <red><bold>Failed to render code:</bold> %s", err))
			}

			_ = tml.Fprintf(
				w,
				"<darkgrey>%s</darkgrey>\n",
				strings.Repeat("─", width),
			)
		}
	}

	if group.Len() > 1 {
		_ = tml.Fprintf(w, "  <dim>Individual Causes\n")
		causeMap := make(map[string]int)
		for _, result := range group.Results() {

			niceFilename := b.Path(result, result.Metadata())

			m := result.Metadata()
			metadata := &m
			for metadata.Parent() != nil {
				metadata = metadata.Parent()
			}
			innerRange := metadata.Range()
			lineInfo := fmt.Sprintf("%d-%d", innerRange.GetStartLine(), innerRange.GetEndLine())
			if !innerRange.IsMultiLine() {
				lineInfo = fmt.Sprintf("%d", innerRange.GetStartLine())
			}
			key := tml.Sprintf("<italic>%s<dim>:%s (%s)", niceFilename, lineInfo, metadata.Reference())
			count := causeMap[key]
			causeMap[key] = count + 1
		}
		for cause, count := range causeMap {
			if count > 1 {
				_ = tml.Fprintf(w, "  <dim>- %s <italic>%d instances\n", cause, count)
			} else {
				_ = tml.Fprintf(w, "  <dim>- %s\n", cause)
			}
		}
		_ = tml.Fprintf(
			w,
			"<darkgrey>%s</darkgrey>\n",
			strings.Repeat("─", width),
		)
	}

	printMetadata(w, first, b.GetLinks(first), isRego)

	_ = tml.Fprintf(
		w,
		"\n<darkgrey>%s</darkgrey>\n\n\n",
		strings.Repeat("─", width),
	)
}

func printMetadata(w io.Writer, result scan.Result, links []string, isRego bool) {
	if isRego {
		_ = tml.Fprintf(w, "  <dim>Rego Package</dim><italic> %s\n", result.RegoNamespace())
		_ = tml.Fprintf(w, "  <dim>   Rego Rule</dim><italic> %s", result.RegoRule())
	} else {
		_ = tml.Fprintf(w, "  <dim>        ID</dim><italic> %s\n", result.Rule().LongID())
		if result.Rule().Impact != "" {
			_ = tml.Fprintf(w, "  <dim>    Impact</dim> %s\n", result.Rule().Impact)
		}
		if result.Rule().Resolution != "" {
			_ = tml.Fprintf(w, "  <dim>Resolution</dim> %s\n", result.Rule().Resolution)
		}
		if len(links) > 0 {
			_ = tml.Fprintf(w, "\n  <dim>More Information</dim>")
		}
		for _, link := range links {
			_ = tml.Fprintf(w, "\n  <dim>-</dim> <blue>%s", link)
		}
	}
}

// nolint
func highlightCode(b formatters.ConfigurableFormatter, result scan.Result, theme string, withColours bool) error {

	codeOpts := []scan.CodeOption{
		scan.OptionCodeWithTruncation(true),
	}

	switch theme {
	case "dark":
		codeOpts = append(codeOpts, scan.OptionCodeWithDarkTheme())
	case "light":
		codeOpts = append(codeOpts, scan.OptionCodeWithLightTheme())
	default:
		codeOpts = append(codeOpts, scan.OptionCodeWithTheme(theme))
	}

	code, err := result.GetCode(codeOpts...)
	if err != nil {
		return err
	}

	w := b.Writer()

	lines := code.Lines

	if len(lines) == 0 {
		return nil
	}

	hasOuter := !lines[0].IsCause || !lines[len(lines)-1].IsCause

	for i, line := range lines {

		outputCode := line.Highlighted
		if !withColours {
			outputCode = line.Content
		}

		// if we're rendering the actual issue lines, use red
		if line.IsCause && result.Status() != scan.StatusPassed {

			// print line number
			_ = tml.Fprintf(
				w,
				"<red>%5d  ",
				line.Number,
			)

			if !hasOuter {
				_ = tml.Fprintf(w, " ")
			} else if code.IsCauseMultiline() {
				switch {
				case line.FirstCause || i == 0:
					_ = tml.Fprintf(w, "<red>┌</red>")
				case line.LastCause || i == len(lines)-1:
					_ = tml.Fprintf(w, "<red>└</red>")
				default:
					_ = tml.Fprintf(w, "<red>│</red>")

				}
			} else {
				_ = tml.Fprintf(w, "<red>[</red>")
			}
			_ = tml.Fprintf(
				w,
				" %s",
				outputCode,
			)
			if line.Annotation != "" && !code.IsCauseMultiline() {
				_ = tml.Fprintf(
					w,
					" <italic><dim>(%s)",
					line.Annotation,
				)
			}
		} else {
			if line.Truncated {

				placeholder := strings.Repeat(" ", 5-len(fmt.Sprintf("%d", line.Number))) + strings.Repeat(".", len(fmt.Sprintf("%d", line.Number)))

				_ = tml.Fprintf(
					w,
					"<darkgrey>%s  ",
					placeholder,
				)
			} else {
				// print line number
				_ = tml.Fprintf(
					w,
					"<darkgrey>%5d  ",
					line.Number,
				)
				_ = tml.Fprintf(
					w,
					"  %s",
					outputCode,
				)
			}

		}
		_, _ = fmt.Fprintln(w, "")
	}

	return nil
}
