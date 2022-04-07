package formatter

import (
	"fmt"
	"io"
	"io/fs"
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

func DefaultWithMetrics(metrics scanner.Metrics, conciseOutput bool) func(b formatters.ConfigurableFormatter, results scan.Results) error {
	return func(b formatters.ConfigurableFormatter, results scan.Results) error {

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
			printResult(b, group)
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

const lineNoWidth = 7

func getStatusOrSeverity(status scan.Status, severity severity.Severity) string {
	switch status {
	case scan.StatusPassed:
		return tml.Sprintf("<green>PASSED</green>")
	case scan.StatusIgnored:
		return tml.Sprintf("<yellow>IGNORED</yellow>")
	default:
		return severityFormat[severity]
	}
}

type simpleLocation struct {
	filename   string
	lineInfo   string
	moduleName string
}

func makeFilenameNice(first scan.Result, baseDir string) (string, string, []simpleLocation) {
	innerRange := first.Range()
	filename := innerRange.GetFilename()
	topFilename := filename
	var via []simpleLocation
	if innerRange.GetSourcePrefix() == "" || strings.HasPrefix(innerRange.GetSourcePrefix(), ".") {
		if relative, err := filepath.Rel(baseDir, filename); err == nil && !strings.Contains(relative, "..") {
			filename = relative
		}
	} else {
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
					parentLineInfo := fmt.Sprintf("Lines %d-%d", parentRange.GetStartLine(), parentRange.GetEndLine())
					if !parentRange.IsMultiLine() {
						parentLineInfo = fmt.Sprintf("Line %d", parentRange.GetStartLine())
					}
					via = append(via, simpleLocation{
						filename:   parentRelative,
						lineInfo:   parentLineInfo,
						moduleName: mod.Reference().String(),
					})
					topFilename = parentRelative
				}
			}

		}
	}
	return filename, topFilename, via
}

// nolint
func printResult(b formatters.ConfigurableFormatter, group formatters.GroupedResult) {

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
	lineInfo := fmt.Sprintf("Lines %d-%d", innerRange.GetStartLine(), innerRange.GetEndLine())
	if !innerRange.IsMultiLine() {
		lineInfo = fmt.Sprintf("Line %d", innerRange.GetStartLine())
	}

	filename, _, via := makeFilenameNice(first, b.BaseDir())

	_ = tml.Fprintf(
		w,
		"<dim>%s\n",
		strings.Repeat("─", width),
	)

	if first.Metadata().Range().GetStartLine() == 0 {
		if filename != "" {
			_ = tml.Fprintf(
				w,
				"<dim>%s%s%s</dim>\n  %s",
				strings.Repeat("─", lineNoWidth),
				"┬",
				strings.Repeat("─", width-lineNoWidth-1),
				filename,
			)
		}
	} else {
		_ = tml.Fprintf(
			w,
			" <italic>%s <dim>%s\n",
			filename,
			lineInfo,
		)
		for i, v := range via {
			_ = tml.Fprintf(
				w,
				" %s<dim>via </dim><italic>%s <dim>%s (%s)\n",
				strings.Repeat(" ", i+1),
				v.filename,
				v.lineInfo,
				v.moduleName,
			)
		}

		_ = tml.Fprintf(
			w,
			"<dim>%s%s%s</dim>\n",
			strings.Repeat("─", lineNoWidth),
			"┬",
			strings.Repeat("─", width-lineNoWidth-1),
		)

		if err := highlightCode(b, first); err != nil {
			printCodeLine(w, -1, tml.Sprintf("<red><bold>Failed to render code:</bold> %s", err))
		}

		_ = tml.Fprintf(
			w,
			"<dim>%s┴%s</dim>\n",
			strings.Repeat("─", lineNoWidth),
			strings.Repeat("─", width-lineNoWidth-1),
		)
	}

	if group.Len() > 1 {
		_ = tml.Fprintf(w, "  <dim>Individual Causes\n")
		for _, result := range group.Results() {

			_, niceFilename, _ := makeFilenameNice(result, b.BaseDir())

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
			_ = tml.Fprintf(w, "  <dim>- %s:%s (%s)\n", niceFilename, lineInfo, metadata.Reference())
		}
		_ = tml.Fprintf(
			w,
			"<dim>%s</dim>\n",
			strings.Repeat("─", width),
		)
	}

	printMetadata(w, first, b.GetLinks(first), isRego)

	_ = tml.Fprintf(
		w,
		"\n<dim>%s</dim>\n\n\n",
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

func printCodeLine(w io.Writer, i int, code string) {
	_ = tml.Fprintf(
		w,
		"<dim>%5d</dim>  <dim>│</dim> %s\n",
		i,
		code,
	)
}

func highlightCode(b formatters.ConfigurableFormatter, result scan.Result) error {

	srcFS := result.Metadata().Range().GetFS()
	if srcFS == nil {
		return fmt.Errorf("code unavailable: no filesystem provided")
	}

	innerRange := result.Range()
	outerRange := innerRange
	if !innerRange.IsMultiLine() {
		metadata := result.Metadata()
		if parent := metadata.Parent(); parent != nil {
			outerRange = parent.Range()
		}
	}

	content, err := fs.ReadFile(srcFS, filepath.ToSlash(innerRange.GetLocalFilename()))
	if err != nil {
		return err
	}

	hasAnnotation := result.Annotation() != ""

	w := b.Writer()

	for i, bodyString := range strings.Split(string(content), "\n") {

		line := i + 1

		// this line is outside the range, skip it
		if line < outerRange.GetStartLine() || line > outerRange.GetEndLine() {
			continue
		}

		// if we're not rendering json, we have an annotation, and we're rendering the line to show the annotation on,
		// render the line with the annotation afterwards
		if !strings.HasSuffix(outerRange.GetFilename(), ".json") && hasAnnotation && line == innerRange.GetStartLine() {
			printCodeLine(w, line, tml.Sprintf("<red>%s</red>        <italic>%s", bodyString, result.Annotation()))
			continue
		}

		// if we're rendering the actual issue lines, use red
		if i+1 >= innerRange.GetStartLine() && i < innerRange.GetEndLine() {
			if result.Status() == scan.StatusPassed {
				printCodeLine(w, line, tml.Sprintf("<green>%s", bodyString))
			} else {
				printCodeLine(w, line, tml.Sprintf("<red>%s", bodyString))
			}
		} else {
			printCodeLine(w, line, tml.Sprintf("<yellow>%s", bodyString))
		}
	}

	return nil
}
