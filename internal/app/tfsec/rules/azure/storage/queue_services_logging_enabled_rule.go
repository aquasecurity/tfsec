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
		LegacyID: "AZU016",
		BadExample: []string{`
 resource "azurerm_storage_account" "bad_example" {
     name                     = "example"
     resource_group_name      = data.azurerm_resource_group.example.name
     location                 = data.azurerm_resource_group.example.location
     account_tier             = "Standard"
     account_replication_type = "GRS"
     queue_properties  {
   }
 }
 `},
		GoodExample: []string{`
 resource "azurerm_storage_account" "good_example" {
     name                     = "example"
     resource_group_name      = data.azurerm_resource_group.example.name
     location                 = data.azurerm_resource_group.example.location
     account_tier             = "Standard"
     account_replication_type = "GRS"
     queue_properties  {
     logging {
         delete                = true
         read                  = true
         write                 = true
         version               = "1.0"
         retention_policy_days = 10
     }
   }
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#logging",
			"https://docs.microsoft.com/en-us/azure/storage/common/storage-analytics-logging?tabs=dotnet",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_storage_account"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("queue_properties") {
				return
			}
			queueProps := resourceBlock.GetBlock("queue_properties")
			if queueProps.MissingChild("logging") {
				results.Add("Resource defines a Queue Services storage account without Storage Analytics logging.", queueProps)
			}

			return results
		},
	})
}
