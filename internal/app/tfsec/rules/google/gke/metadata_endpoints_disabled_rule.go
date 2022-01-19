package gke

import (
	"github.com/aquasecurity/defsec/rules/google/gke"
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
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_container_cluster"},
		Base:           gke.CheckMetadataEndpointsDisabled,
	})
}
