package gke

import (
	"github.com/aquasecurity/defsec/rules/google/gke"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "GCP012",
		BadExample: []string{`
 resource "google_container_cluster" "bad_example" {
 	node_config {
 	}
 }
 `},
		GoodExample: []string{`
 resource "google_container_cluster" "good_example" {
 	node_config {
 		service_account = "cool-service-account@example.com"
 	}
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#service_account",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_container_cluster", "google_container_node_pool"},
		Base:           gke.CheckUseServiceAccount,
	})
}
