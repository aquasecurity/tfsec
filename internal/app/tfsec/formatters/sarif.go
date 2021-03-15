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

	run := report.AddRun("tfsec", "https://tfsec.dev")

	// TODO - Handle if the --include-passed argument is passed.

	for _, result := range results {
		rule := run.AddRule(string(result.RuleID)).
			WithDescription(result.Description).
			WithHelp(result.Link)

		relativePath, err := filepath.Rel(baseDir, result.Range.Filename)
		if err != nil {
			return err
		}

		ruleResult := run.AddResult(rule.ID).
			WithMessage(string(result.RuleDescription)).
			WithLevel(strings.ToLower(string(result.Severity))).
			WithLocationDetails(relativePath, result.Range.StartLine, 1)

		run.AddResultDetails(rule, ruleResult, result.Range.Filename)
	}

	return report.PrettyWrite(w)
}
