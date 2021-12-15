package keyvault

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AZU021",
		BadExample: []string{`
 resource "azurerm_key_vault" "bad_example" {
     name                        = "examplekeyvault"
     location                    = azurerm_resource_group.bad_example.location
     enabled_for_disk_encryption = true
     purge_protection_enabled    = false
 }
 `},
		GoodExample: []string{`
 resource "azurerm_key_vault" "good_example" {
     name                        = "examplekeyvault"
     location                    = azurerm_resource_group.good_example.location
     enabled_for_disk_encryption = true
     soft_delete_retention_days  = 7
     purge_protection_enabled    = true
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault#purge_protection_enabled",
			"https://docs.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview#purge-protection",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_key_vault"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("purge_protection_enabled") {
				results.Add("Resource should have purge protection enabled.", resourceBlock)
				return
			}
			purgeProtectionAttr := resourceBlock.GetAttribute("purge_protection_enabled")
			if purgeProtectionAttr.IsFalse() {
				results.Add("Resource should have purge protection enabled.", purgeProtectionAttr)
				return
			}

			if resourceBlock.MissingChild("soft_delete_retention_days") || resourceBlock.GetAttribute("soft_delete_retention_days").LessThan(1) {
				results.Add("Resource should have soft_delete_retention_days set in order to enabled purge protection.", resourceBlock)
			}
			return results
		},
	})
}
