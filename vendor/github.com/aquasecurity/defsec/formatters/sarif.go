package formatters

import (
	"io"
	"path/filepath"

<<<<<<< HEAD:internal/app/tfsec/formatters/sarif.go
	"github.com/aquasecurity/tfsec/pkg/severity"
	"github.com/owenrumney/go-sarif/sarif"

	"github.com/aquasecurity/tfsec/pkg/result"
=======
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"

	"github.com/owenrumney/go-sarif/sarif"
>>>>>>> Tests passing, building:vendor/github.com/aquasecurity/defsec/formatters/sarif.go
)

func FormatSarif(w io.Writer, results []rules.Result, baseDir string, _ ...FormatterOption) error {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return err
	}

	run := sarif.NewRun("tfsec", "https://tfsec.dev")
	report.AddRun(run)

	for _, res := range results {

		if res.Status() == rules.StatusPassed {
			continue
		}

		var link string
		if len(res.Rule().Links) > 0 {
			link = res.Rule().Links[0]
		}
<<<<<<< HEAD:internal/app/tfsec/formatters/sarif.go
		rule := run.AddRule(res.RuleID).
			WithDescription(res.RuleSummary).
			WithHelpURI(link)
=======
		rule := run.AddRule(res.Rule().LongID()).
			WithDescription(res.Rule().Summary).
			WithHelp(link)
>>>>>>> Tests passing, building:vendor/github.com/aquasecurity/defsec/formatters/sarif.go

		rng := res.NarrowestRange()

		relativePath, err := filepath.Rel(baseDir, rng.GetFilename())
		if err != nil {
			return err
		}
		if baseDir == rng.GetFilename() {
			relativePath = filepath.Base(baseDir)
		}

		message := sarif.NewTextMessage(res.Description())
		region := sarif.NewSimpleRegion(rng.GetStartLine(), rng.GetEndLine())
		var level string
		switch res.Severity() {
		case severity.None:
			level = "none"
		case severity.Low:
			level = "note"
		case severity.Medium:
			level = "warning"
		case severity.High, severity.Critical:
			level = "error"
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
