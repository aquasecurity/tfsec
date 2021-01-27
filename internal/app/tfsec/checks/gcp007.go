package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"
)

// GkeLegacyMetadataEndpoints See https://github.com/tfsec/tfsec#included-checks for check info
const GkeLegacyMetadataEndpoints scanner.RuleCode = "GCP007"
const GkeLegacyMetadataEndpointsDescription scanner.RuleSummary = "Legacy metadata endpoints enabled."
const GkeLegacyMetadataEndpointsExplanation = `
The Compute Engine instance metadata server exposes legacy v0.1 and v1beta1 endpoints, which do not enforce metadata query headers. 

This is a feature in the v1 APIs that makes it more difficult for a potential attacker to retrieve instance metadata. 

Unless specifically required, we recommend you disable these legacy APIs.

When setting the <code>metadata</code> block, the default value for <code>disable-legacy-endpoints</code> is set to true, they should not be explicitly enabled.
`
const GkeLegacyMetadataEndpointsBadExample = `
resource "google_container_cluster" "gke" {
	metadata {
    disable-legacy-endpoints = false
  }
}`
const GkeLegacyMetadataEndpointsGoodExample = `
resource "google_container_cluster" "gke" {
	metadata {
    disable-legacy-endpoints = true
  }
}`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: GkeLegacyMetadataEndpoints,
		Documentation: scanner.CheckDocumentation{
			Summary:     GkeLegacyMetadataEndpointsDescription,
			Explanation: GkeLegacyMetadataEndpointsExplanation,
			BadExample:  GkeLegacyMetadataEndpointsBadExample,
			GoodExample: GkeLegacyMetadataEndpointsGoodExample,
			Links: []string{
				"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#protect_node_metadata_default_for_112",
				"https://www.terraform.io/docs/providers/google/r/container_cluster.html#metadata",
			},
		},
		Provider:       scanner.GCPProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_container_cluster"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			legacyMetadataAPI := block.GetBlock("metadata").GetAttribute("disable-legacy-endpoints")
			if legacyMetadataAPI.Type() == cty.String && legacyMetadataAPI.Value().AsString() != "true" || legacyMetadataAPI.Type() == cty.Bool && legacyMetadataAPI.Value().False() {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines a cluster with legacy metadata endpoints enabled.", block.FullName()),
						legacyMetadataAPI.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
