package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"
)

// GkeNodeMetadataExposed See https://github.com/tfsec/tfsec#included-checks for check info
const GkeNodeMetadataExposed scanner.RuleCode = "GCP006"
const GkeNodeMetadataExposedDescription scanner.RuleSummary = "Node metadata value disables metadata concealment."
const GkeNodeMetadataExposedExplanation = `
If the <code>workflow_metadata_config</code> block is included the the <code>node_metadata</code> attribute is required. 

The attribute should be set to <code>SPECIFIED</code> to ensure that the the VM metadata is not unnecessarily exposed to pods.

`
const GkeNodeMetadataExposedBadExample = `
resource "google_container_cluster" "gke" {
	workload_metadata_config {
		node_metadata = "EXPOSE"
	}
}`
const GkeNodeMetadataExposedGoodExample = `
resource "google_container_cluster" "gke" {
	workload_metadata_config {
		node_metadata = "SPECIFIED"
	}
}`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: GkeNodeMetadataExposed,
		Documentation: scanner.CheckDocumentation{
			Summary:     GkeNodeMetadataExposedDescription,
			Explanation: GkeNodeMetadataExposedExplanation,
			BadExample:  GkeNodeMetadataExposedBadExample,
			GoodExample: GkeNodeMetadataExposedGoodExample,
			Links: []string{
				"https://cloud.google.com/kubernetes-engine/docs/how-to/protecting-cluster-metadata#create-concealed",
				"https://www.terraform.io/docs/providers/google/r/container_cluster.html#node_metadata",
			},
		},
		Provider:       scanner.GCPProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_container_cluster"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			nodeMetadata := block.GetBlock("workload_metadata_config").GetAttribute("node_metadata")

			if nodeMetadata != nil && nodeMetadata.Type() == cty.String &&
				(nodeMetadata.Value().AsString() == "EXPOSE" || nodeMetadata.Value().AsString() == "UNSPECIFIED") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines a cluster with node metadata exposed. node_metadata set to EXPOSE or UNSPECIFIED disables metadata concealment. ", block.Name()),
						nodeMetadata.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
