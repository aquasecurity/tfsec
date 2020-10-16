package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

// GkeAbacEnabled See https://github.com/tfsec/tfsec#included-checks for check info
const GkeAbacEnabled scanner.RuleCode = "GCP005"
const GkeAbacEnabledDescription scanner.RuleSummary = "Legacy ABAC permissions are enabled."
const GkeAbacEnabledExplanation = `

`
const GkeAbacEnabledBadExample = `

`
const GkeAbacEnabledGoodExample = `

`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: GkeAbacEnabled,
		Documentation: scanner.CheckDocumentation{
			Summary:     GkeAbacEnabledDescription,
			Explanation: GkeAbacEnabledExplanation,
			BadExample:  GkeAbacEnabledBadExample,
			GoodExample: GkeAbacEnabledGoodExample,
			Links:       []string{},
		},
		Provider:       scanner.GCPProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_container_cluster"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			enable_legacy_abac := block.GetAttribute("enable_legacy_abac")
			if enable_legacy_abac.Value().AsString() == "true" {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines a cluster with ABAC enabled. Disable and rely on RBAC instead. https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#leave_abac_disabled_default_for_110", block.Name()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
