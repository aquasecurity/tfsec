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
		LegacyID:  "GCP007",
		Service:   "gke",
		ShortCode: "metadata-endpoints-disabled",
		Documentation: rule.RuleDocumentation{
			Summary:    "Legacy metadata endpoints enabled.",
			Impact:     "Legacy metadata endpoints don't require metadata headers",
			Resolution: "Disable legacy metadata endpoints",
			Explanation: `
The Compute Engine instance metadata server exposes legacy v0.1 and v1beta1 endpoints, which do not enforce metadata query headers. 

This is a feature in the v1 APIs that makes it more difficult for a potential attacker to retrieve instance metadata. 

Unless specifically required, we recommend you disable these legacy APIs.

When setting the <code>metadata</code> block, the default value for <code>disable-legacy-endpoints</code> is set to true, they should not be explicitly enabled.
`,
			BadExample: []string{`
resource "google_container_cluster" "bad_example" {
	metadata {
    disable-legacy-endpoints = false
  }
}`},
			GoodExample: []string{`
resource "google_container_cluster" "good_example" {
	metadata {
    disable-legacy-endpoints = true
  }
}`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#metadata",
				"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#protect_node_metadata_default_for_112",
			},
		},
		Provider:        provider.GoogleProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_container_cluster"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("metadata") {
				return
			}

			legacyMetadataAPI := resourceBlock.GetNestedAttribute("metadata.disable-legacy-endpoints")
			if legacyMetadataAPI.IsNotNil() && legacyMetadataAPI.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' defines a cluster with legacy metadata endpoints enabled.", resourceBlock.FullName())
			}

		},
	})
}
