package rules

import (
	"fmt"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"
)

// GkeNodeMetadataExposed See https://github.com/tfsec/tfsec#included-checks for check info
const GkeNodeMetadataExposed = "GCP006"
const GkeNodeMetadataExposedDescription = "Node metadata value disables metadata concealment."
const GkeNodeMetadataExposedImpact = "Metadata that isn't concealed potentially risks leakage of sensitive data"
const GkeNodeMetadataExposedResolution = "Set node metadata to SECURE or GKE_METADATA_SERVER"
const GkeNodeMetadataExposedExplanation = `
If the <code>workload_metadata_config</code> block within <code>node_config</code> is included, the <code>node_metadata</code> attribute should be configured securely.

The attribute should be set to <code>SECURE</code> to use metadata concealment, or <code>GKE_METADATA_SERVER</code> if workload identity is enabled. This ensures that the VM metadata is not unnecessarily exposed to pods.

`
const GkeNodeMetadataExposedBadExample = `
resource "google_container_node_pool" "bad_example" {
	node_config {
		workload_metadata_config {
			node_metadata = "EXPOSE"
		}
	}
}`
const GkeNodeMetadataExposedGoodExample = `
resource "google_container_node_pool" "good_example" {
	node_config {
		workload_metadata_config {
			node_metadata = "SECURE"
		}
	}
}`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: GkeNodeMetadataExposed,
		Documentation: rule.RuleDocumentation{
			Summary:     GkeNodeMetadataExposedDescription,
			Impact:      GkeNodeMetadataExposedImpact,
			Resolution:  GkeNodeMetadataExposedResolution,
			Explanation: GkeNodeMetadataExposedExplanation,
			BadExample:  GkeNodeMetadataExposedBadExample,
			GoodExample: GkeNodeMetadataExposedGoodExample,
			Links: []string{
				"https://cloud.google.com/kubernetes-engine/docs/how-to/protecting-cluster-metadata#create-concealed",
				"https://www.terraform.io/docs/providers/google/r/container_cluster.html#node_metadata",
			},
		},
		Provider:        provider.GCPProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_container_cluster", "google_container_node_pool"},
		DefaultSeverity: severity.Error,
		CheckFunc: func(set result.Set, resourceBlock *block.Block, _ *hclcontext.Context) {

			nodeMetadata := resourceBlock.GetBlock("node_config").GetBlock("workload_metadata_config").GetAttribute("node_metadata")

			if nodeMetadata != nil && nodeMetadata.Type() == cty.String &&
				(nodeMetadata.Value().AsString() == "EXPOSE" || nodeMetadata.Value().AsString() == "UNSPECIFIED") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines a cluster with node metadata exposed. node_metadata set to EXPOSE or UNSPECIFIED disables metadata concealment. ", resourceBlock.FullName())).
						WithRange(nodeMetadata.Range()).
						WithSeverity(severity.Error),
				)
			}

		},
	})
}
