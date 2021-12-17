package formatters

import (
	"io"
	"path/filepath"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

func FormatSarif(w io.Writer, results []rules.Result, baseDir string, _ ...FormatterOption) error {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return err
	}

	run := sarif.NewRunWithInformationURI("tfsec", "https://tfsec.dev")
	report.AddRun(run)

	for _, res := range results {

		if res.Status() == rules.StatusPassed {
			continue
		}

		var link string
		if len(res.Rule().Links) > 0 {
			link = res.Rule().Links[0]
		}
		rule := run.AddRule(res.Rule().LongID()).
			WithDescription(res.Rule().Summary).
			WithHelpURI(link)

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

		ruleResult := run.CreateResultForRule(rule.ID)

		ruleResult.WithMessage(message).
			WithLevel(level).
			AddLocation(sarif.NewLocation().WithPhysicalLocation(location))
	}

	return report.PrettyWrite(w)
}
