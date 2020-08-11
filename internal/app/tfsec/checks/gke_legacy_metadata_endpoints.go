package checks

import (
	"fmt"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"
)

// GkeLegacyMetadataEndpoints See https://github.com/liamg/tfsec#included-checks for check info
const GkeLegacyMetadataEndpoints scanner.RuleID = "GCP007"

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           GkeLegacyMetadataEndpoints,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_container_cluster"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			legacyMetadataAPI := block.GetBlock("metadata").GetAttribute("disable-legacy-endpoints")
      if legacyMetadataAPI.Type() == cty.String && legacyMetadataAPI.Value().AsString() != "true" || legacyMetadataAPI.Type() == cty.Bool && legacyMetadataAPI.Value().False() {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines a cluster with legacy metadata endpoints enabled. See: https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#protect_node_metadata_default_for_112", block.Name()),
						legacyMetadataAPI.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
