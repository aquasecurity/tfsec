package storage

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AZU014",
		BadExample: []string{`
 resource "azurerm_storage_account" "bad_example" {
   name                      = "storageaccountname"
   resource_group_name       = azurerm_resource_group.example.name
   location                  = azurerm_resource_group.example.location
   account_tier              = "Standard"
   account_replication_type  = "GRS"
   enable_https_traffic_only = false
 }
 `},
		GoodExample: []string{`
 resource "azurerm_storage_account" "good_example" {
   name                      = "storageaccountname"
   resource_group_name       = azurerm_resource_group.example.name
   location                  = azurerm_resource_group.example.location
   account_tier              = "Standard"
   account_replication_type  = "GRS"
   enable_https_traffic_only = true
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#enable_https_traffic_only",
			"https://docs.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_storage_account"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.HasChild("enable_https_traffic_only") {

				httpsOnlyAttr := resourceBlock.GetAttribute("enable_https_traffic_only")

				if httpsOnlyAttr.IsFalse() {
					results.Add("Resource explicitly turns off secure transfer to storage account.", httpsOnlyAttr)
				}
			}

			return results
		},
	})
}
