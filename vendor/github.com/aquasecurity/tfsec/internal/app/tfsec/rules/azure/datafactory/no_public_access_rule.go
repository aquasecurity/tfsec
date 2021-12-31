package datafactory

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/azure/datafactory"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AZU025",
		BadExample: []string{`
 resource "azurerm_data_factory" "bad_example" {
   name                = "example"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
 }
 `},
		GoodExample: []string{`
 resource "azurerm_data_factory" "good_example" {
   name                = "example"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   public_network_enabled = false
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/data_factory#public_network_enabled",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_data_factory"},
		Base:           datafactory.CheckNoPublicAccess,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("public_network_enabled") {
				results.Add("Resource should have public_network_enabled set to false, the default is true.", resourceBlock)
				return
			}
			publicAccessAttr := resourceBlock.GetAttribute("public_network_enabled")
			if publicAccessAttr.IsTrue() {
				results.Add("Resource should not have public network set to true.", publicAccessAttr)
			}
			return results
		},
	})
}
