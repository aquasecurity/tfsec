package gke

// generator-locked
import (
	"strings"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "GCP012",
		Service:   "gke",
		ShortCode: "use-service-account",
		Documentation: rule.RuleDocumentation{
			Summary:    "Checks for service account defined for GKE nodes",
			Impact:     "Service accounts with wide permissions can increase the risk of compromise",
			Resolution: "Use limited permissions for service accounts to be effective",
			Explanation: `
You should create and use a minimally privileged service account to run your GKE cluster instead of using the Compute Engine default service account.
`,
			BadExample: []string{`
resource "google_container_cluster" "bad_example" {
	node_config {
	}
}
`},
			GoodExample: []string{`
resource "google_container_cluster" "good_example" {
	node_config {
		service_account = "cool-service-account@example.com"
	}
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#service_account",
				"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#use_least_privilege_sa",
			},
		},
		Provider:        provider.GoogleProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_container_cluster", "google_container_node_pool"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if strings.HasPrefix(resourceBlock.Label(), "google_container_cluster") {
				attr := resourceBlock.GetAttribute("remove_default_node_pool")
				if attr.IsNotNil() && attr.IsTrue() {
					return
				}
			}

			if resourceBlock.MissingChild("node_config") {
				set.AddResult().
					WithDescription("Resource '%s' does not define the node config and does not override the default service account. It is recommended to use a minimally privileged service account to run your GKE cluster.", resourceBlock.FullName())
				return
			}

			nodeConfigBlock := resourceBlock.GetBlock("node_config")
			serviceAccount := nodeConfigBlock.GetAttribute("service_account")

			if serviceAccount.IsNil() || serviceAccount.IsEmpty() {
				set.AddResult().
					WithDescription("Resource '%s' does not override the default service account. It is recommended to use a minimally privileged service account to run your GKE cluster.", resourceBlock.FullName())
			}

		},
	})
}
