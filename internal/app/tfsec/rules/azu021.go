package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const AZUKeyVaultPurgeProtection = "AZU021"
const AZUKeyVaultPurgeProtectionDescription = "Key vault should have purge protection enabled"
const AZUKeyVaultPurgeProtectionImpact = "Keys could be purged from the vault without protection"
const AZUKeyVaultPurgeProtectionResolution = "Enable purge protection for key vaults"
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
	scanner.RegisterCheckRule(rule.Rule{
		ID: AZUKeyVaultPurgeProtection,
		Documentation: rule.RuleDocumentation{
			Summary:     AZUKeyVaultPurgeProtectionDescription,
			Impact:      AZUKeyVaultPurgeProtectionImpact,
			Resolution:  AZUKeyVaultPurgeProtectionResolution,
			Explanation: AZUKeyVaultPurgeProtectionExplanation,
			BadExample:  AZUKeyVaultPurgeProtectionBadExample,
			GoodExample: AZUKeyVaultPurgeProtectionGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault#purge_protection_enabled",
				"https://docs.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview#purge-protection",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_key_vault"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if resourceBlock.MissingChild("purge_protection_enabled") || resourceBlock.GetAttribute("purge_protection_enabled").IsFalse() {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' should have purge protection enabled.", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}
			if resourceBlock.MissingChild("soft_delete_retention_days") || resourceBlock.GetAttribute("soft_delete_retention_days").LessThan(1) {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' should have soft_delete_retention_days set in order to enabled purge protection.", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
			}
		},
	})
}
