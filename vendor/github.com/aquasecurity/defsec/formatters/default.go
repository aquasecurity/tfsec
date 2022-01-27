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

	groups, err := b.GroupResults(results)
	if err != nil {
		return err
	}

	fmt.Fprintln(b.Writer(), "")
	for _, group := range groups {
		printResult(b, group)
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

func printResult(b configurableFormatter, group GroupedResult) {

	first := group.Results()[0]

	var severityFormatted string
	if first.Status() == rules.StatusPassed {
		severityFormatted = tml.Sprintf("<green>PASSED</green>")
	} else {
		severityFormatted = severityFormat[first.Severity()]
	}

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

	tml.Fprintf(
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

	filename := innerRange.GetFilename()
	if relative, err := filepath.Rel(b.BaseDir(), filename); err == nil {
		filename = relative
	}

	tml.Fprintf(
		w,
		"<dim>%s\n",
		strings.Repeat("─", width),
	)

	if first.Status() != rules.StatusPassed {
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

		if err := highlightCode(b, first); err != nil {
			printCodeLine(w, -1, tml.Sprintf("<red><bold>Failed to render code:</bold> %s", err))
		}

		tml.Fprintf(
			w,
			"<dim>%s┴%s</dim>\n",
			strings.Repeat("─", lineNoWidth),
			strings.Repeat("─", width-lineNoWidth-1),
		)
	}

	if group.Len() > 1 {
		tml.Printf("  <dim>Individual Causes\n")
		for _, result := range group.Results() {
			m := result.Metadata()
			metadata := &m
			for metadata.Parent() != nil {
				metadata = metadata.Parent()
			}
			tml.Printf("  <dim>- %s (%s)\n", metadata.Range(), metadata.Reference())
		}
		tml.Fprintf(
			w,
			"<dim>%s</dim>\n",
			strings.Repeat("─", width),
		)
	}

	_ = tml.Fprintf(w, "  <dim>        ID</dim> <italic>%s\n", first.Rule().LongID())
	if first.Rule().Impact != "" {
		_ = tml.Fprintf(w, "  <dim>    Impact</dim> %s\n", first.Rule().Impact)
	}
	if first.Rule().Resolution != "" {
		_ = tml.Fprintf(w, "  <dim>Resolution</dim> %s\n", first.Rule().Resolution)
	}

	links := b.GetLinks(first)
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

	innerRange := result.Range()
	outerRange := innerRange
	if !innerRange.IsMultiLine() {
		metadata := result.Metadata()
		if parent := metadata.Parent(); parent != nil {
			outerRange = parent.Range()
		}
	}

	content, err := ioutil.ReadFile(innerRange.GetFilename())
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
