package formatters

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/owenrumney/go-sarif/sarif"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func FormatSarif(w io.Writer, results []scanner.Result, baseDir string) error {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return err
	}

	run := report.AddRun("tfsec", "https://tfsec.dev")

	for _, result := range results {
		rule := run.AddRule(string(result.RuleID)).
			WithDescription(result.Description).
			WithHelp(fmt.Sprintf("You can lean more about %s at https://tfsec.dev/%s/%s", result.RuleID, strings.ToLower(string(result.RuleProvider)), result.RuleID))

		relativePath, err := filepath.Rel(baseDir, result.Range.Filename)
		if err != nil {
			return err
		}

		ruleResult := run.AddResult(rule.Id).
			WithMessage(string(result.RuleDescription)).
			WithLevel(strings.ToLower(string(result.Severity))).
			WithLocationDetails(relativePath, result.Range.StartLine, 1)

		run.AddResultDetails(rule, ruleResult, result.Range.Filename)
	}

	return report.PrettyWrite(w)
}
