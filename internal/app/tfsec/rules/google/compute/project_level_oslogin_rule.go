package compute

import (
	"github.com/aquasecurity/defsec/rules/google/compute"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
 resource "google_compute_project_metadata" "default" {
   metadata = {
 	enable-oslogin = false
   }
 }
 `},
		GoodExample: []string{`
 resource "google_compute_project_metadata" "default" {
   metadata = {
     enable-oslogin = true
   }
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_project_metadata#",
		},
		Base: compute.CheckProjectLevelOslogin,
	})
}
