package checks

import (
	"fmt"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"
	
	"github.com/zclconf/go-cty/cty"
)

// GkeShieldedNodesDisabled See https://github.com/liamg/tfsec#included-checks for check info
const GkeShieldedNodesDisabled scanner.RuleID = "GCP010"

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           GkeShieldedNodesDisabled,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_container_cluster"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			enable_shielded_nodes := block.GetAttribute("enable_shielded_nodes")

			if enable_shielded_nodes == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines a cluster with shielded nodes disabled. Shielded GKE Nodes provide strong, verifiable node identity and integrity to increase the security of GKE nodes and should be enabled on all GKE clusters. https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#shielded_nodes", block.Name()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			if enable_shielded_nodes.Type() == cty.Bool && enable_shielded_nodes.Value().False() || enable_shielded_nodes.Type() == cty.String && enable_shielded_nodes.Value().AsString() != "true" {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines a cluster with shielded nodes disabled. Shielded GKE Nodes provide strong, verifiable node identity and integrity to increase the security of GKE nodes and should be enabled on all GKE clusters. https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#shielded_nodes", block.Name()),
						enable_shielded_nodes.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
