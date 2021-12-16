package project

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
 resource "google_project" "bad_example" {
   name       = "My Project"
   project_id = "your-project-id"
   org_id     = "1234567"
   auto_create_network = true
 }
 `},
		GoodExample: []string{`
 resource "google_project" "good_example" {
   name       = "My Project"
   project_id = "your-project-id"
   org_id     = "1234567"
   auto_create_network = false
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project#auto_create_network",
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"google_project",
		},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			if autoCreateNetworkAttr := resourceBlock.GetAttribute("auto_create_network"); autoCreateNetworkAttr.IsNil() { // alert on use of default value
				results.Add("Resource uses default value for auto_create_network", ?)
			} else if autoCreateNetworkAttr.IsTrue() {
				results.Add("Resource does not have auto_create_network set to false", autoCreateNetworkAttr)
			}
			return results
		},
	})
}
