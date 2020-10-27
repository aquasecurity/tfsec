package formatters

import (
	"fmt"
	"io"
	"os"
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
			WithLevel(strings.ToLower(string(result.Severity))).
			WithLocationDetails(getRelativePath(result.Range.Filename), result.Range.StartLine, 1)

		run.AddResultDetails(rule, ruleResult, result.Range.Filename)
	}

	return report.PrettyWrite(w)
}

func getRelativePath(fullPath string) string {
	checkRootPath := os.Getenv("ABSOLUTE_CHECK_PATH")
	relativePath := strings.TrimPrefix(strings.ReplaceAll(fullPath, checkRootPath, ""), "/")
	return relativePath
}
