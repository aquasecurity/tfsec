package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
	"github.com/zclconf/go-cty/cty"
)

const GCPGKENodeServiceAccount scanner.RuleCode = "GCP012"
const GCPGKENodeServiceAccountDescription scanner.RuleSummary = "Checks for service account defined for GKE nodes"
const GCPGKENodeServiceAccountExplanation = `
You should create and use a minimally privileged service account to run your GKE cluster instead of using the Compute Engine default service account.
`

const GCPGKENodeServiceAccountBadExample = `
resource "google_container_cluster" "my-cluster" {
  node_config {
  }
}
`
const GCPGKENodeServiceAccountGoodExample = `
resource "google_container_cluster" "my-cluster" {
  node_config {
    service_account = "cool-service-account@example.com"
  }
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: GCPGKENodeServiceAccount,
		Documentation: scanner.CheckDocumentation{
			Summary:     GCPGKENodeServiceAccountDescription,
			Explanation: GCPGKENodeServiceAccountExplanation,
			BadExample:  GCPGKENodeServiceAccountBadExample,
			GoodExample: GCPGKENodeServiceAccountGoodExample,
			Links: []string{
				"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#use_least_privilege_sa",
			},
		},
		Provider:       scanner.GCPProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_container_cluster", "google_container_node_pool"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			display_block := block.GetBlock("node_config")
			service_account := display_block.GetAttribute("service_account")

			if service_account == nil || (service_account.Value().Type() != cty.String) || len(service_account.Value().AsString()) == 0 {
				if display_block == nil {
					display_block = block
				}

				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not override the default service account. It is recommended to use a minimally privileged service account to run your GKE cluster.", block.FullName()),
						display_block.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
