package checks

import (
	"fmt"
	"strings"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
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

			if strings.HasPrefix(block.Label(), "google_container_cluster") && block.GetAttribute("remove_default_node_pool").IsTrue() {
				return nil
			}

			if !block.HasBlock("node_config") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not define the node config and does not override the default service account. It is recommended to use a minimally privileged service account to run your GKE cluster.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}
			displayBlock := block.GetBlock("node_config")
			serviceAccount := displayBlock.GetAttribute("service_account")

			if serviceAccount == nil || serviceAccount.IsEmpty() {
				if displayBlock == nil {
					displayBlock = block
				}

				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not override the default service account. It is recommended to use a minimally privileged service account to run your GKE cluster.", block.FullName()),
						displayBlock.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
