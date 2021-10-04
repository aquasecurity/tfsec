package keyvault

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AZU021",
		Service:   "keyvault",
		ShortCode: "no-purge",
		Documentation: rule.RuleDocumentation{
			Summary:    "Key vault should have purge protection enabled",
			Impact:     "Keys could be purged from the vault without protection",
			Resolution: "Enable purge protection for key vaults",
			Explanation: `
Purge protection is an optional Key Vault behavior and is not enabled by default.

Purge protection can only be enabled once soft-delete is enabled. It can be turned on via CLI or PowerShell.
`,
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
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_key_vault"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("purge_protection_enabled") {
				set.AddResult().
					WithDescription("Resource '%s' should have purge protection enabled.", resourceBlock.FullName())
				return
			}
			purgeProtectionAttr := resourceBlock.GetAttribute("purge_protection_enabled")
			if purgeProtectionAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' should have purge protection enabled.", resourceBlock.FullName()).WithAttribute(purgeProtectionAttr)
				return
			}

			if resourceBlock.MissingChild("soft_delete_retention_days") || resourceBlock.GetAttribute("soft_delete_retention_days").LessThan(1) {
				set.AddResult().
					WithDescription("Resource '%s' should have soft_delete_retention_days set in order to enabled purge protection.", resourceBlock.FullName())
			}
		},
	})
}
