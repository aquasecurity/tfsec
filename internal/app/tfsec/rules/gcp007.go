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

// GkeLegacyMetadataEndpoints See https://github.com/tfsec/tfsec#included-checks for check info
const GkeLegacyMetadataEndpoints = "GCP007"
const GkeLegacyMetadataEndpointsDescription = "Legacy metadata endpoints enabled."
const GkeLegacyMetadataEndpointsImpact = "Legacy metadata endpoints don't require metadata headers"
const GkeLegacyMetadataEndpointsResolution = "Disable legacy metadata endpoints"
const GkeLegacyMetadataEndpointsExplanation = `
The Compute Engine instance metadata server exposes legacy v0.1 and v1beta1 endpoints, which do not enforce metadata query headers. 

This is a feature in the v1 APIs that makes it more difficult for a potential attacker to retrieve instance metadata. 

Unless specifically required, we recommend you disable these legacy APIs.

When setting the <code>metadata</code> block, the default value for <code>disable-legacy-endpoints</code> is set to true, they should not be explicitly enabled.
`
const GkeLegacyMetadataEndpointsBadExample = `
resource "google_container_cluster" "bad_example" {
	metadata {
    disable-legacy-endpoints = false
  }
}`
const GkeLegacyMetadataEndpointsGoodExample = `
resource "google_container_cluster" "good_example" {
	metadata {
    disable-legacy-endpoints = true
  }
}`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: GkeLegacyMetadataEndpoints,
		Documentation: rule.RuleDocumentation{
			Summary:     GkeLegacyMetadataEndpointsDescription,
			Impact:      GkeLegacyMetadataEndpointsImpact,
			Resolution:  GkeLegacyMetadataEndpointsResolution,
			Explanation: GkeLegacyMetadataEndpointsExplanation,
			BadExample:  GkeLegacyMetadataEndpointsBadExample,
			GoodExample: GkeLegacyMetadataEndpointsGoodExample,
			Links: []string{
				"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#protect_node_metadata_default_for_112",
				"https://www.terraform.io/docs/providers/google/r/container_cluster.html#metadata",
			},
		},
		Provider:       provider.GCPProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_container_cluster"},
		CheckFunc: func(set result.Set, resourceBlock *block.Block, _ *hclcontext.Context) {

			legacyMetadataAPI := resourceBlock.GetBlock("metadata").GetAttribute("disable-legacy-endpoints")
			if legacyMetadataAPI.Type() == cty.String && legacyMetadataAPI.Value().AsString() != "true" || legacyMetadataAPI.Type() == cty.Bool && legacyMetadataAPI.Value().False() {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines a cluster with legacy metadata endpoints enabled.", resourceBlock.FullName())).
						WithRange(legacyMetadataAPI.Range()).
						WithSeverity(severity.Error),
				)
			}

		},
	})
}
