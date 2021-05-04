package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AzureUnencryptedManagedDisk See https://github.com/tfsec/tfsec#included-checks for check info
const AzureUnencryptedManagedDisk scanner.RuleCode = "AZU003"
const AzureUnencryptedManagedDiskDescription scanner.RuleSummary = "Unencrypted managed disk."
const AzureUnencryptedManagedDiskImpact = "Data could be read if compromised"
const AzureUnencryptedManagedDiskResolution = "Enable encryption on managed disks"
const AzureUnencryptedManagedDiskExplanation = `
Manage disks should be encrypted at rest. When specifying the <code>encryption_settings</code> block, the enabled attribute should be set to <code>true</code>.
`
const AzureUnencryptedManagedDiskBadExample = `
resource "azurerm_managed_disk" "bad_example" {
	encryption_settings {
		enabled = false
	}
}`
const AzureUnencryptedManagedDiskGoodExample = `
resource "azurerm_managed_disk" "good_example" {
	encryption_settings {
		enabled = true
	}
}`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AzureUnencryptedManagedDisk,
		Documentation: scanner.CheckDocumentation{
			Summary:     AzureUnencryptedManagedDiskDescription,
			Impact:      AzureUnencryptedManagedDiskImpact,
			Resolution:  AzureUnencryptedManagedDiskResolution,
			Explanation: AzureUnencryptedManagedDiskExplanation,
			BadExample:  AzureUnencryptedManagedDiskBadExample,
			GoodExample: AzureUnencryptedManagedDiskGoodExample,
			Links: []string{
				"https://docs.microsoft.com/en-us/azure/virtual-machines/linux/disk-encryption",
				"https://www.terraform.io/docs/providers/azurerm/r/managed_disk.html",
			},
		},
		Provider:       scanner.AzureProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_managed_disk"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			encryptionSettingsBlock := block.GetBlock("encryption_settings")
			if encryptionSettingsBlock == nil {
				return nil // encryption is by default now, so this is fine
			}

			enabledAttr := encryptionSettingsBlock.GetAttribute("enabled")
			if enabledAttr != nil && enabledAttr.IsFalse() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf(
							"Resource '%s' defines an unencrypted managed disk.",
							block.FullName(),
						),
						enabledAttr.Range(),
						enabledAttr,
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
