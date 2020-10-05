package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

// GkeAbacEnabled See https://github.com/tfsec/tfsec#included-checks for check info
const GkeAbacEnabled scanner.RuleID = "GCP005"
const GkeAbacEnabledDescription scanner.RuleDescription = "Legacy ABAC permissions are enabled."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           GkeAbacEnabled,
		Description:    GkeAbacEnabledDescription,
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
