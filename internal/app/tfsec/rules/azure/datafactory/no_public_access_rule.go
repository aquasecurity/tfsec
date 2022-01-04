package datafactory

import (
	"github.com/aquasecurity/defsec/rules/azure/datafactory"
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
	})
}
