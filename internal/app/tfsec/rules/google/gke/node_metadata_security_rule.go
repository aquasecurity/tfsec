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
		LegacyID:  "GCP006",
		Service:   "gke",
		ShortCode: "node-metadata-security",
		Documentation: rule.RuleDocumentation{
			Summary:    "Node metadata value disables metadata concealment.",
			Impact:     "Metadata that isn't concealed potentially risks leakage of sensitive data",
			Resolution: "Set node metadata to SECURE or GKE_METADATA_SERVER",
			Explanation: `
If the <code>workload_metadata_config</code> block within <code>node_config</code> is included, the <code>node_metadata</code> attribute should be configured securely.

The attribute should be set to <code>SECURE</code> to use metadata concealment, or <code>GKE_METADATA_SERVER</code> if workload identity is enabled. This ensures that the VM metadata is not unnecessarily exposed to pods.

`,
			BadExample: []string{`
resource "google_container_node_pool" "bad_example" {
	node_config {
		workload_metadata_config {
			node_metadata = "EXPOSE"
		}
	}
}`},
			GoodExample: []string{`
resource "google_container_node_pool" "good_example" {
	node_config {
		workload_metadata_config {
			node_metadata = "SECURE"
		}
	}
}`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#node_metadata",
				"https://cloud.google.com/kubernetes-engine/docs/how-to/protecting-cluster-metadata#create-concealed",
			},
		},
		Provider:        provider.GoogleProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_container_cluster", "google_container_node_pool"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingNestedChild("node_config.workload_metadata_config.node_metadata") {
				return
			}

			nodeMetadata := resourceBlock.GetNestedAttribute("node_config.workload_metadata_config.node_metadata")
			if nodeMetadata.IsAny("EXPOSE", "UNSPECIFIED") {
				set.AddResult().
					WithDescription("Resource '%s' defines a cluster with node metadata exposed. node_metadata set to EXPOSE or UNSPECIFIED disables metadata concealment. ", resourceBlock.FullName())
			}

		},
	})
}
