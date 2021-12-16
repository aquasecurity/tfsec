package gke

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/google/gke"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "GCP007",
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
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_container_cluster"},
		Base:           gke.CheckMetadataEndpointsDisabled,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("metadata") {
				return
			}

			legacyMetadataAPI := resourceBlock.GetNestedAttribute("metadata.disable-legacy-endpoints")
			if legacyMetadataAPI.IsNotNil() && legacyMetadataAPI.IsFalse() {
				results.Add("Resource defines a cluster with legacy metadata endpoints enabled.", legacyMetadataAPI)
			}

			return results
		},
	})
}
