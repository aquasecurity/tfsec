package gke

import (
	"github.com/aquasecurity/defsec/rules/google/gke"
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
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_container_cluster", "google_container_node_pool"},
		Base:           gke.CheckNodeMetadataSecurity,
	})
}
