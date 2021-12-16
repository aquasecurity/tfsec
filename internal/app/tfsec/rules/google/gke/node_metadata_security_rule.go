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
		LegacyID: "GCP006",
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
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_container_cluster", "google_container_node_pool"},
		Base:           gke.CheckNodeMetadataSecurity,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingNestedChild("node_config.workload_metadata_config.node_metadata") {
				return
			}

			nodeMetadata := resourceBlock.GetNestedAttribute("node_config.workload_metadata_config.node_metadata")
			if nodeMetadata.IsAny("EXPOSE", "UNSPECIFIED") {
				results.Add("Resource defines a cluster with node metadata exposed. node_metadata set to EXPOSE or UNSPECIFIED disables metadata concealment. ", nodeMetadata)
			}

			return results
		},
	})
}
