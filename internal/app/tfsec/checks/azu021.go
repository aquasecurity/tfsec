package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AZUKeyVaultPurgeProtection scanner.RuleCode = "AZU021"
const AZUKeyVaultPurgeProtectionDescription scanner.RuleSummary = "Key vault should have purge protection enabled"
const AZUKeyVaultPurgeProtectionExplanation = `
Purge protection is an optional Key Vault behavior and is not enabled by default.

Purge protection can only be enabled once soft-delete is enabled. It can be turned on via CLI or PowerShell.
`
const AZUKeyVaultPurgeProtectionBadExample = `
resource "azurerm_key_vault" "bad_example" {
    name                        = "examplekeyvault"
    location                    = azurerm_resource_group.bad_example.location
    enabled_for_disk_encryption = true
    purge_protection_enabled    = false
}
`
const AZUKeyVaultPurgeProtectionGoodExample = `
resource "azurerm_key_vault" "good_example" {
    name                        = "examplekeyvault"
    location                    = azurerm_resource_group.good_example.location
    enabled_for_disk_encryption = true
    soft_delete_retention_days  = 7
    purge_protection_enabled    = true
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AZUKeyVaultPurgeProtection,
		Documentation: scanner.CheckDocumentation{
			Summary:     AZUKeyVaultPurgeProtectionDescription,
			Explanation: AZUKeyVaultPurgeProtectionExplanation,
			BadExample:  AZUKeyVaultPurgeProtectionBadExample,
			GoodExample: AZUKeyVaultPurgeProtectionGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault#purge_protection_enabled",
				"https://docs.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview#purge-protection",
			},
		},
		Provider:       scanner.AzureProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_key_vault"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.MissingChild("purge_protection_enabled") || block.GetAttribute("purge_protection_enabled").IsFalse() || (block.GetAttribute("purge_protection_enabled").IsTrue() && (block.MissingChild("soft_delete_retention_days") || block.GetAttribute("soft_delete_retention_days").LessThan(1))) {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' should have purge protection enabled.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
