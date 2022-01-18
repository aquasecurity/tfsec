package gke

import (
	"github.com/aquasecurity/defsec/rules/google/gke"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "GCP005",
		BadExample: []string{`
 resource "google_container_cluster" "bad_example" {
 	enable_legacy_abac = true
 }
 `},
		GoodExample: []string{`
 resource "google_container_cluster" "good_example" {
 	# ...
 	# enable_legacy_abac not set
 	# ...
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#enable_legacy_abac",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_container_cluster"},
		Base:           gke.CheckUseRbacPermissions,
	})
}
