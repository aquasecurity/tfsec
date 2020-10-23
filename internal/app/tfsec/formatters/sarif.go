package formatters

import (
	"fmt"
	"io"
	"strings"

	"github.com/owenrumney/go-sarif/sarif"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func FormatSarif(w io.Writer, results []scanner.Result) error {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return err
	}

	run := report.AddRun("tfsec", "https://tfsec.dev")

	for _, result := range results {
		rule := run.AddRule(string(result.RuleID)).
			WithDescription(result.Description).
			WithHelpUri(fmt.Sprintf("https://tfsec.dev/%s/%s", strings.ToLower(string(result.RuleProvider)), result.RuleID))

		ruleResult := run.AddResult(rule.Id).
			WithMessage(string(result.RuleDescription)).
			WithLevel(string(result.Severity)).
			WithLocationDetails(result.Range.Filename, result.Range.StartLine, 1)

		run.AddResultDetails(rule, ruleResult, result.Range.Filename)
	}

	return report.Write(w)
}
