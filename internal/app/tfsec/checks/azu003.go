package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AzureUnencryptedManagedDisk See https://github.com/tfsec/tfsec#included-checks for check info
const AzureUnencryptedManagedDisk scanner.RuleCode = "AZU003"
const AzureUnencryptedManagedDiskDescription scanner.RuleSummary = "Unencrypted managed disk."
const AzureUnencryptedManagedDiskExplanation = `
Manage disks should be encrypted at rest. When specifying the <code>encryption_settings</code> block, the enabled attribute should be set to <code>true</code>.
`
const AzureUnencryptedManagedDiskBadExample = `
resource "azurerm_managed_disk" "my-disk" {
	encryption_settings {
		enabled = false
	}
}`
const AzureUnencryptedManagedDiskGoodExample = `
resource "azurerm_managed_disk" "my-disk" {
	encryption_settings {
		enabled = true
	}
}`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AzureUnencryptedManagedDisk,
		Documentation: scanner.CheckDocumentation{
			Summary:     AzureUnencryptedManagedDiskDescription,
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
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf(
							"Resource '%s' defines an unencrypted managed disk.",
							block.FullName(),
						),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			enabledAttr := encryptionSettingsBlock.GetAttribute("enabled")
			if enabledAttr != nil && enabledAttr.Type() == cty.Bool && enabledAttr.Value().False() {
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
