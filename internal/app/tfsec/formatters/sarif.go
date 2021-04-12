package formatters

import (
	"io"
	"path/filepath"
	"strings"

	"github.com/owenrumney/go-sarif/sarif"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func FormatSarif(w io.Writer, results []scanner.Result, baseDir string, options ...FormatterOption) error {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return err
	}

	run := sarif.NewRun("tfsec", "https://tfsec.dev")
	report.AddRun(run)

	// TODO - Handle if the --include-passed argument is passed.

	for _, result := range results {
		rule := run.AddRule(string(result.RuleID)).
			WithDescription(string(result.RuleDescription)).
			WithHelp(result.Link)

		relativePath, err := filepath.Rel(baseDir, result.Range.Filename)
		if err != nil {
			return err
		}

		message := sarif.NewMessage().
			WithText(string(result.Description))
		region := sarif.NewRegion().
			WithStartLine(result.Range.StartLine).
			WithEndLine(result.Range.EndLine)

		location := sarif.NewPhysicalLocation().
			WithArtifactLocation(
				sarif.NewArtifactLocation().
					WithUri(relativePath)).
			WithRegion(region)

		ruleResult := run.AddResult(rule.ID)
		ruleResult.WithMessage(*message).
			WithLevel(strings.ToLower(string(result.Severity))).
			WithLocation(sarif.NewLocation().WithPhysicalLocation(location))
	}

	return report.PrettyWrite(w)
}
