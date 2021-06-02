package rules

import (
	"fmt"
	"strings"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const GCPGKENodeServiceAccount = "GCP012"
const GCPGKENodeServiceAccountDescription = "Checks for service account defined for GKE nodes"
const GCPGKENodeServiceAccountImpact = "Service accounts with wide permissions can increase the risk of compromise"
const GCPGKENodeServiceAccountResolution = "Use limited permissions for service accounts to be effective"
const GCPGKENodeServiceAccountExplanation = `
You should create and use a minimally privileged service account to run your GKE cluster instead of using the Compute Engine default service account.
`

const GCPGKENodeServiceAccountBadExample = `
resource "google_container_cluster" "bad_example" {
	node_config {
	}
}
`
const GCPGKENodeServiceAccountGoodExample = `
resource "google_container_cluster" "good_example" {
	node_config {
		service_account = "cool-service-account@example.com"
	}
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: GCPGKENodeServiceAccount,
		Documentation: rule.RuleDocumentation{
			Summary:     GCPGKENodeServiceAccountDescription,
			Impact:      GCPGKENodeServiceAccountImpact,
			Resolution:  GCPGKENodeServiceAccountResolution,
			Explanation: GCPGKENodeServiceAccountExplanation,
			BadExample:  GCPGKENodeServiceAccountBadExample,
			GoodExample: GCPGKENodeServiceAccountGoodExample,
			Links: []string{
				"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#use_least_privilege_sa",
			},
		},
		Provider:       provider.GCPProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_container_cluster", "google_container_node_pool"},
		CheckFunc: func(set result.Set, block *block.Block, _ *hclcontext.Context) {

			if strings.HasPrefix(block.Label(), "google_container_cluster") && block.GetAttribute("remove_default_node_pool").IsTrue() {
				return nil
			}

			if !block.HasBlock("node_config") {
				set.Add(
					result.New().WithDescription(
						fmt.Sprintf("Resource '%s' does not define the node config and does not override the default service account. It is recommended to use a minimally privileged service account to run your GKE cluster.", block.FullName()),
						).WithRange(block.Range()).WithSeverity(
						severity.Error,
					),
				}
			}
			displayBlock := block.GetBlock("node_config")
			serviceAccount := displayBlock.GetAttribute("service_account")

			if serviceAccount == nil || serviceAccount.IsEmpty() {
				if displayBlock == nil {
					displayBlock = block
				}

				set.Add(
					result.New().WithDescription(
						fmt.Sprintf("Resource '%s' does not override the default service account. It is recommended to use a minimally privileged service account to run your GKE cluster.", block.FullName()),
						display).WithRange(block.Range()).WithSeverity(
						severity.Error,
					),
				}
			}

			return nil
		},
	})
}
