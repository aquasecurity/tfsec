package gke

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)


func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:   "GCP010",
		Service:   "gke",
		ShortCode: "node-shielding-enabled",
		Documentation: rule.RuleDocumentation{
			Summary:      "Shielded GKE nodes not enabled.",
			Impact:       "Node identity and integrity can't be verified without shielded GKE nodes",
			Resolution:   "Enable node shielding",
			Explanation:  `
CIS GKE Benchmark Recommendation: 6.5.5. Ensure Shielded GKE Nodes are Enabled

Shielded GKE Nodes provide strong, verifiable node identity and integrity to increase the security of GKE nodes and should be enabled on all GKE clusters.
`,
			BadExample:   `
resource "google_container_cluster" "bad_example" {
	enable_shielded_nodes = "false"
}`,
			GoodExample:  `
resource "google_container_cluster" "good_example" {
	enable_shielded_nodes = "true"
}`,
			Links: []string{
				"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#shielded_nodes",
				"https://www.terraform.io/docs/providers/google/r/container_cluster.html#enable_shielded_nodes",
			},
		},
		Provider:        provider.GCPProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_container_cluster"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if resourceBlock.MissingChild("enable_shielded_nodes") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines a cluster with shielded nodes disabled. Shielded GKE Nodes provide strong, verifiable node identity and integrity to increase the security of GKE nodes and should be enabled on all GKE clusters.", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}

			enableShieldedNodesAttr := resourceBlock.GetAttribute("enable_shielded_nodes")
			if enableShieldedNodesAttr != nil && enableShieldedNodesAttr.IsFalse() {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines a cluster with shielded nodes disabled. Shielded GKE Nodes provide strong, verifiable node identity and integrity to increase the security of GKE nodes and should be enabled on all GKE clusters.", resourceBlock.FullName())).
						WithRange(enableShieldedNodesAttr.Range()),
				)
			}

		},
	})
}
