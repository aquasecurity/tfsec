package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"
)

// GkeShieldedNodesDisabled See https://github.com/tfsec/tfsec#included-checks for check info
const GkeShieldedNodesDisabled scanner.RuleCode = "GCP010"
const GkeShieldedNodesDisabledDescription scanner.RuleSummary = "Shielded GKE nodes not enabled."
const GkeShieldedNodesDisabledExplanation = `
CIS GKE Benchmark Recommendation: 6.5.5. Ensure Shielded GKE Nodes are Enabled

Shielded GKE Nodes provide strong, verifiable node identity and integrity to increase the security of GKE nodes and should be enabled on all GKE clusters.
`
const GkeShieldedNodesDisabledBadExample = `
resource "google_container_cluster" "gke" {
	enable_shielded_nodes = "false"
}`
const GkeShieldedNodesDisabledGoodExample = `
resource "google_container_cluster" "gke" {
	enable_shielded_nodes = "true"
}`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: GkeShieldedNodesDisabled,
		Documentation: scanner.CheckDocumentation{
			Summary:     GkeShieldedNodesDisabledDescription,
			Explanation: GkeShieldedNodesDisabledExplanation,
			BadExample:  GkeShieldedNodesDisabledBadExample,
			GoodExample: GkeShieldedNodesDisabledGoodExample,
			Links: []string{
				"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#shielded_nodes",
				"https://www.terraform.io/docs/providers/google/r/container_cluster.html#enable_shielded_nodes",
			},
		},
		Provider:       scanner.GCPProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_container_cluster"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			enable_shielded_nodes := block.GetAttribute("enable_shielded_nodes")

			if enable_shielded_nodes == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines a cluster with shielded nodes disabled. Shielded GKE Nodes provide strong, verifiable node identity and integrity to increase the security of GKE nodes and should be enabled on all GKE clusters.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			if enable_shielded_nodes.Type() == cty.Bool && enable_shielded_nodes.Value().False() || enable_shielded_nodes.Type() == cty.String && enable_shielded_nodes.Value().AsString() != "true" {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines a cluster with shielded nodes disabled. Shielded GKE Nodes provide strong, verifiable node identity and integrity to increase the security of GKE nodes and should be enabled on all GKE clusters.", block.FullName()),
						enable_shielded_nodes.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
