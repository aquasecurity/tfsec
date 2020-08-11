package checks

import (
	"fmt"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"
)

// GkeNodeMetadataExposed See https://github.com/liamg/tfsec#included-checks for check info
const GkeNodeMetadataExposed scanner.RuleID = "GCP006"

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           GkeNodeMetadataExposed,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_container_cluster"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			nodeMetadata := block.GetBlock("workload_metadata_config").GetAttribute("node_metadata")

      if nodeMetadata.Type() == cty.String && nodeMetadata.Value().AsString() == "EXPOSE" || nodeMetadata.Type() == cty.String && nodeMetadata.Value().AsString() == "UNSPECIFIED" {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines a cluster with node metadata exposed. node_metadata set to EXPOSE or UNSPECIFIED disables metadata concealment. https://cloud.google.com/kubernetes-engine/docs/how-to/protecting-cluster-metadata#create-concealed", block.Name()),
						nodeMetadata.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
