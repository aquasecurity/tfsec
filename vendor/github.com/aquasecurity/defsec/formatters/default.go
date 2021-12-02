package formatters

import (
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/liamg/clinch/terminal"
	"github.com/liamg/gifwrap/pkg/ascii"
	"github.com/liamg/tml"
)

var severityFormat map[severity.Severity]string

func FormatDefault(_ io.Writer, results []rules.Result, _ string, options ...FormatterOption) error {

	showSuccessOutput := true
	includePassedChecks := false

	var showGif bool

	for _, option := range options {
		switch option {
		case IncludePassed:
			includePassedChecks = true
		case ConciseOutput:
			showSuccessOutput = false
		case PassingGif:
			showGif = true
		case NoColour:
			tml.DisableFormatting()
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

	if len(results) == 0 || len(results) == countPassedResults(results) {
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
		printResult(res, i, includePassedChecks)
	}

	terminal.PrintErrorf("\n  %d potential problems detected.\n\n", len(results)-countPassedResults(results))

	return nil

}

func printResult(res rules.Result, i int, includePassedChecks bool) {

	resultHeader := fmt.Sprintf("  <underline>Result %d</underline>\n", i+1)

	var severityFormatted string
	if includePassedChecks && res.Status() == rules.StatusPassed {
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

	if code, err := highlightCode(res); err == nil {
		_ = tml.Printf(code)
		tml.Println("\n")
	} else if err != nil {
		terminal.PrintErrorf("Source code not available\n\n")
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

func highlightCode(result rules.Result) (string, error) {

	rng := result.CodeBlockMetadata().Range()

	if rng == nil {
		return "", nil
	}
	var resolvedValue string
	content, err := ioutil.ReadFile(rng.GetFilename())
	if err != nil {
		return "", err
	}

	hasAnnotation := result.Annotation() != "" && result.IssueBlockMetadata() != nil

	bodyStrings := strings.Split(string(content), "\n")

	var coloured []string
	for i, bodyString := range bodyStrings {
		resolvedValue = ""
		if i >= rng.GetStartLine()-1 && i <= rng.GetEndLine() {
			// TODO: Fix this for json
			if !strings.HasSuffix(rng.GetFilename(), ".json") {
				if hasAnnotation && result.IssueBlockMetadata().Range().GetStartLine() == i+1 {
					resolvedValue = fmt.Sprintf("<blue>[%s]</blue>", result.Annotation())
				}
			}

			if hasAnnotation {
				if resolvedValue == "" {
					coloured = append(coloured, fmt.Sprintf("<blue>% 5d</blue> <dim>┃</dim> <yellow>%s</yellow>", i, bodyString))
				} else {
					coloured = append(coloured, fmt.Sprintf("<blue>% 5d</blue> <dim>┃</dim> <red>%s    %s</red>", i, bodyString, resolvedValue))
				}
			} else {
				coloured = append(coloured, fmt.Sprintf("<blue>% 5d</blue> <dim>┃</dim> <red>%s</red>", i, bodyString))

			}
		}
	}

	return strings.Join(coloured, "\n"), nil

}
