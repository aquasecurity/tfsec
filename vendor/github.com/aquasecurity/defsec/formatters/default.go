package formatters

import (
	"fmt"
	"io"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/liamg/clinch/terminal"
	"github.com/liamg/tml"
)

var severityFormat map[severity.Severity]string

func outputDefault(b configurableFormatter, results []rules.Result) error {

	// we initialise the map here so we respect the colour-ignore options
	severityFormat = map[severity.Severity]string{
		severity.Low:      tml.Sprintf("<white>%s</white>", severity.Low),
		severity.Medium:   tml.Sprintf("<yellow>%s</yellow>", severity.Medium),
		severity.High:     tml.Sprintf("<red>%s</red>", severity.High),
		severity.Critical: tml.Sprintf("<bold><red>%s</red></bold>", severity.Critical),
		"":                tml.Sprintf("<white> UNKNOWN</white>"),
	}

	passCount := countPassedResults(results)

	if len(results) == 0 || len(results) == passCount {
		b.PrintMetrics()
		tml.Fprintf(b.Writer(), "\n<green><bold>No problems detected!\n\n")
		return nil
	}

	fmt.Fprintln(b.Writer(), "")
	for i, res := range results {
		printResult(b, res, i)
	}

	b.PrintMetrics()

	var passInfo string
	if passCount > 0 {
		passInfo = fmt.Sprintf("%d passed, ", passCount)
	}
	tml.Fprintf(b.Writer(), "\n  <red><bold>%s%d potential problem(s) detected.\n\n", passInfo, len(results)-countPassedResults(results))

	return nil

}

const lineNoWidth = 7

var indent = strings.Repeat(" ", lineNoWidth+2)

func printResult(b configurableFormatter, res rules.Result, i int) {

	var severityFormatted string
	if res.Status() == rules.StatusPassed {
		severityFormatted = tml.Sprintf("<green>PASSED</green>")
	} else {
		severityFormatted = severityFormat[res.Severity()]
	}

	width, _ := terminal.Size()
	if width <= 0 {
		width = 80
	}

	w := b.Writer()

	tml.Fprintf(
		w,
		" <italic>#%d</italic> %s <bold>%s</bold>\n",
		i+1,
		severityFormatted,
		res.Description(),
	)

	rng := res.CodeBlockMetadata().Range()
	if res.IssueBlockMetadata() != nil {
		rng = res.IssueBlockMetadata().Range()
	}
	lineInfo := fmt.Sprintf("Line %d", rng.GetStartLine())
	if rng.GetStartLine() < rng.GetEndLine() {
		lineInfo = fmt.Sprintf("Lines %d-%d", rng.GetStartLine(), rng.GetEndLine())
	}
	filename := rng.GetFilename()
	if relative, err := filepath.Rel(b.BaseDir(), filename); err == nil {
		filename = relative
	}

	tml.Fprintf(
		w,
		"<dim>%s\n",
		strings.Repeat("─", width),
	)
	tml.Fprintf(
		w,
		" <italic>%s <dim>%s\n",
		filename,
		lineInfo,
	)

	tml.Fprintf(
		w,
		"<dim>%s%s%s</dim>\n",
		strings.Repeat("─", lineNoWidth),
		"┬",
		strings.Repeat("─", width-lineNoWidth-1),
	)

	if err := highlightCode(b, res); err != nil {
		printCodeLine(w, -1, tml.Sprintf("<red><bold>Failed to render code:</bold> %s", err))
	}

	tml.Fprintf(
		w,
		"<dim>%s┴%s</dim>\n",
		strings.Repeat("─", lineNoWidth),
		strings.Repeat("─", width-lineNoWidth-1),
	)

	_ = tml.Fprintf(w, "  <dim>        ID</dim> <italic>%s\n", res.Rule().LongID())
	if res.Rule().Impact != "" {
		_ = tml.Fprintf(w, "  <dim>    Impact</dim> %s\n", res.Rule().Impact)
	}
	if res.Rule().Resolution != "" {
		_ = tml.Fprintf(w, "  <dim>Resolution</dim> %s\n", res.Rule().Resolution)
	}

	links := b.GetLinks(res)
	if len(links) > 0 {
		_ = tml.Fprintf(w, "\n  <dim>More Information</dim>")
	}
	for _, link := range links {
		_ = tml.Fprintf(w, "\n  <dim>-</dim> <blue>%s", link)
	}

	tml.Fprintf(
		w,
		"\n<dim>%s</dim>\n\n\n",
		strings.Repeat("─", width),
	)
}

func countPassedResults(results []rules.Result) int {
	passed := 0

	for _, res := range results {
		if res.Status() == rules.StatusPassed {
			passed++
		}
	}

	return passed
}

func printCodeLine(w io.Writer, i int, code string) {
	_ = tml.Fprintf(
		w,
		"<dim>%5d</dim>  <dim>│</dim> %s\n",
		i,
		code,
	)
}

func highlightCode(b configurableFormatter, result rules.Result) error {

	outerRange := result.CodeBlockMetadata().Range()
	innerRange := outerRange
	if result.IssueBlockMetadata() != nil {
		innerRange = result.IssueBlockMetadata().Range()
	}

	content, err := ioutil.ReadFile(outerRange.GetFilename())
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
			if result.Status() == rules.StatusPassed {
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

func printResultLegacy(b configurableFormatter, res rules.Result, i int) {

	resultHeader := fmt.Sprintf("  <underline>Result %d</underline>\n", i+1)

	var severityFormatted string
	if res.Status() == rules.StatusPassed {
		terminal.PrintSuccessf(resultHeader)
		severityFormatted = tml.Sprintf("<green>PASSED</green>")
	} else {
		terminal.PrintErrorf(resultHeader)
		severityFormatted = severityFormat[res.Severity()]
	}

	rng := res.CodeBlockMetadata().Range()
	if res.IssueBlockMetadata() != nil {
		rng = res.IssueBlockMetadata().Range()
	}

	w := b.Writer()

	_ = tml.Fprintf(w, `
  <blue>[</blue>%s<blue>]</blue> %s
  <blue>%s</blue>

`, severityFormatted, res.Description(), rng)

	if err := highlightCode(b, res); err != nil {
		_ = tml.Fprintf(w, "<red>Failed to render source code: %s</red>\n", err)
	}

	_ = tml.Fprintf(w, "  <white>ID:         </white><blue>%s</blue>\n", res.Rule().LongID())
	if res.Rule().Impact != "" {
		_ = tml.Fprintf(w, "  <white>Impact:     </white><blue>%s</blue>\n", res.Rule().Impact)
	}
	if res.Rule().Resolution != "" {
		_ = tml.Fprintf(w, "  <white>Resolution: </white><blue>%s</blue>\n", res.Rule().Resolution)
	}

	links := b.GetLinks(res)
	if len(links) > 0 {
		_ = tml.Fprintf(w, "\n  <white>More Info:</white>")
	}
	for _, link := range links {
		_ = tml.Fprintf(w, "\n  -<blue> %s </blue>", link)
	}
	fmt.Fprintf(w, "\n\n")
}
