package formatters

import (
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/aquasecurity/defsec/metrics"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/liamg/clinch/terminal"
	"github.com/liamg/gifwrap/pkg/ascii"
	"github.com/liamg/tml"
)

var severityFormat map[severity.Severity]string

func FormatDefault(_ io.Writer, results []rules.Result, _ string, options ...FormatterOption) error {

	showDebug := false
	showSuccessOutput := true
	showMetrics := true

	var showGif bool

	for _, option := range options {
		switch option {
		case ConciseOutput:
			showSuccessOutput = false
			showMetrics = false
		case PassingGif:
			showGif = true
			showMetrics = false
		case NoColour:
			tml.DisableFormatting()
		case WithDebug:
			showDebug = true
		}
	}

	if severityFormat == nil {
		severityFormat = map[severity.Severity]string{
			severity.Low:      tml.Sprintf("<white>%s</white>", severity.Low),
			severity.Medium:   tml.Sprintf("<yellow>%s</yellow>", severity.Medium),
			severity.High:     tml.Sprintf("<red>%s</red>", severity.High),
			severity.Critical: tml.Sprintf("<bold><red>%s</red></bold>", severity.Critical),
			"":                tml.Sprintf("<white>UNKNOWN</white>"),
		}
	}

	passCount := countPassedResults(results)

	if len(results) == 0 || len(results) == passCount {
		if showGif {
			if renderer, err := ascii.FromURL("https://media.giphy.com/media/kyLYXonQYYfwYDIeZl/source.gif"); err == nil {
				renderer.SetFill(true)
				_ = renderer.PlayOnce()
			}
		}
		if showSuccessOutput {
			terminal.PrintSuccessf("\nNo problems detected!\n\n")
		}
		return nil
	}

	fmt.Println("")
	for i, res := range results {
		printResult(res, i)
	}

	if showMetrics {
		printMetrics(showDebug)
	}

	var passInfo string
	if passCount > 0 {
		passInfo = fmt.Sprintf("%d passed, ", passCount)
	}

	terminal.PrintErrorf("\n  %s%d potential problems detected.\n\n", passInfo, len(results)-countPassedResults(results))

	return nil

}

func printMetrics(debug bool) {

	categories := metrics.General()

	if debug {
		categories = append(categories, metrics.Debug()...)
	}

	for _, category := range categories {
		_ = tml.Printf("  <blue>%s</blue>\n  %s\n", category.Name(), strings.Repeat("-", 42))
		for _, metric := range category.Metrics() {
			_ = tml.Printf("  <blue>%-20s</blue> %s\n", metric.Name(), metric.Value())
		}
		fmt.Printf("\n")
	}

}

func printResult(res rules.Result, i int) {

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

	_ = tml.Printf(`
  <blue>[</blue>%s<blue>]</blue> %s
  <blue>%s</blue>

`, severityFormatted, res.Description(), rng)

	if err := highlightCode(res); err != nil {
		_ = tml.Printf("<red>Failed to render source code: %s</red>\n", err)
	}

	_ = tml.Printf("  <white>ID:         </white><blue>%s</blue>\n", res.Rule().LongID())
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
		_ = tml.Printf("\n  -<blue> %s </blue>", link)
	}
	fmt.Printf("\n\n")
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

func highlightCode(result rules.Result) error {

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

	for i, bodyString := range strings.Split(string(content), "\n") {

		line := i + 1

		// this line is outside the range, skip it
		if line < outerRange.GetStartLine() || line > outerRange.GetEndLine() {
			continue
		}

		// if we're not rendering json, we have an annotation, and we're rendering the line to show the annotation on,
		// render the line with the annotation afterwards
		if !strings.HasSuffix(outerRange.GetFilename(), ".json") && hasAnnotation && line == innerRange.GetStartLine() {
			annotation := tml.Sprintf("<blue>[%s]</blue>", result.Annotation())
			_ = tml.Printf("<blue>% 5d</blue> <dim>┃</dim> <red>%s    %s</red>\n", line, bodyString, annotation)
			continue
		}

		// if we're rendering the actual issue lines, use red
		if i+1 >= innerRange.GetStartLine() && i < innerRange.GetEndLine() {
			if result.Status() == rules.StatusPassed {
				_ = tml.Printf("<blue>% 5d</blue> <dim>┃</dim> <green>%s</green>\n", line, bodyString)
			} else {
				_ = tml.Printf("<blue>% 5d</blue> <dim>┃</dim> <red>%s</red>\n", line, bodyString)
			}
		} else {
			_ = tml.Printf("<blue>% 5d</blue> <dim>┃</dim> <yellow>%s</yellow>\n", line, bodyString)
		}
	}

	fmt.Printf("\n\n")
	return nil
}
