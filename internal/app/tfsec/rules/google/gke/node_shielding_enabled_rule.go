package gke

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "GCP010",
		Service:   "gke",
		ShortCode: "node-shielding-enabled",
		Documentation: rule.RuleDocumentation{
			Summary:    "Shielded GKE nodes not enabled.",
			Impact:     "Node identity and integrity can't be verified without shielded GKE nodes",
			Resolution: "Enable node shielding",
			Explanation: `
CIS GKE Benchmark Recommendation: 6.5.5. Ensure Shielded GKE Nodes are Enabled

Shielded GKE Nodes provide strong, verifiable node identity and integrity to increase the security of GKE nodes and should be enabled on all GKE clusters.
`,
			BadExample: []string{`
resource "google_container_cluster" "bad_example" {
	enable_shielded_nodes = "false"
}`},
			GoodExample: []string{`
resource "google_container_cluster" "good_example" {
	enable_shielded_nodes = "true"
}`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#enable_shielded_nodes",
				"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#shielded_nodes",
			},
		},
		Provider:        provider.GoogleProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_container_cluster"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("enable_shielded_nodes") {
				set.AddResult().
					WithDescription("Resource '%s' defines a cluster with shielded nodes disabled. Shielded GKE Nodes provide strong, verifiable node identity and integrity to increase the security of GKE nodes and should be enabled on all GKE clusters.", resourceBlock.FullName())
				return
			}

			enableShieldedNodesAttr := resourceBlock.GetAttribute("enable_shielded_nodes")
			if enableShieldedNodesAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' defines a cluster with shielded nodes disabled. Shielded GKE Nodes provide strong, verifiable node identity and integrity to increase the security of GKE nodes and should be enabled on all GKE clusters.", resourceBlock.FullName())
			}

		},
	})
}
