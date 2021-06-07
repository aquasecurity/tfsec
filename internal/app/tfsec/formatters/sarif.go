package formatters

import (
	"io"
	"path/filepath"
	"strings"

	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/result"

	"github.com/owenrumney/go-sarif/sarif"
)

func FormatSarif(w io.Writer, results []result.Result, baseDir string, _ ...FormatterOption) error {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return err
	}

	run := sarif.NewRun("tfsec", "https://tfsec.dev")
	report.AddRun(run)

	for _, res := range results {

		if res.Passed() {
			continue
		}

		var link string
		if len(res.Links) > 0 {
			link = res.Links[0]
		}
		rule := run.AddRule(res.RuleID).
			WithDescription(res.RuleSummary).
			WithHelp(link)

		relativePath, err := filepath.Rel(baseDir, res.Range.Filename)
		if err != nil {
			return err
		}

		message := sarif.NewTextMessage(res.Description)
		region := sarif.NewSimpleRegion(res.Range.StartLine, res.Range.EndLine)
		level := strings.ToLower(string(res.Severity))
		if res.Severity == severity.Info {
			level = "note"
		}

		location := sarif.NewPhysicalLocation().
			WithArtifactLocation(sarif.NewSimpleArtifactLocation(relativePath)).
			WithRegion(region)

		ruleResult := run.AddResult(rule.ID)

		ruleResult.WithMessage(message).
			WithLevel(level).
			WithLocation(sarif.NewLocation().WithPhysicalLocation(location))
	}

	return report.PrettyWrite(w)
}
