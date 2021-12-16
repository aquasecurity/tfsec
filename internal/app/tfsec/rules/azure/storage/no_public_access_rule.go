package storage

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/azure/storage"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/zclconf/go-cty/cty"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AZU011",
		BadExample: []string{`
 resource "azure_storage_container" "bad_example" {
 	name                  = "terraform-container-storage"
 	container_access_type = "blob"
 	
 	properties = {
 		"publicAccess" = "blob"
 	}
 }
 `},
		GoodExample: []string{`
 resource "azure_storage_container" "good_example" {
 	name                  = "terraform-container-storage"
 	container_access_type = "blob"
 	
 	properties = {
 		"publicAccess" = "off"
 	}
 }
 `},
		Links: []string{
			"https://www.terraform.io/docs/providers/azure/r/storage_container.html#properties",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azure_storage_container"},
		Base:           storage.CheckNoPublicAccess,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("properties") {
				return
			}
			properties := resourceBlock.GetAttribute("properties")
			if properties.Contains("publicAccess") {
				value := properties.MapValue("publicAccess")
				if value == cty.StringVal("blob") || value == cty.StringVal("container") {
					results.Add("Resource should disable public access.", properties)
				}
			}
			return results
		},
	})
}
