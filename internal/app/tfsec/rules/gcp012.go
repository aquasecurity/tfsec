package rules

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
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
		Provider:        provider.GCPProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_container_cluster", "google_container_node_pool"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if strings.HasPrefix(resourceBlock.Label(), "google_container_cluster") {
				attr := resourceBlock.GetAttribute("remove_default_node_pool")
				if attr != nil && attr.IsTrue() {
					return
				}
			}

			if resourceBlock.MissingChild("node_config") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' does not define the node config and does not override the default service account. It is recommended to use a minimally privileged service account to run your GKE cluster.", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}

			nodeConfigBlock := resourceBlock.GetBlock("node_config")
			serviceAccount := nodeConfigBlock.GetAttribute("service_account")

			if serviceAccount == nil || serviceAccount.IsEmpty() {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' does not override the default service account. It is recommended to use a minimally privileged service account to run your GKE cluster.", resourceBlock.FullName())).
						WithRange(nodeConfigBlock.Range()),
				)
			}

		},
	})
}
