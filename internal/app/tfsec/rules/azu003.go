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

const AzureUnencryptedManagedDisk = "AZU003"
const AzureUnencryptedManagedDiskDescription = "Unencrypted managed disk."
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
	scanner.RegisterCheckRule(rule.Rule{
		ID: AzureUnencryptedManagedDisk,
		Documentation: rule.RuleDocumentation{
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
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_managed_disk"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {
			encryptionSettingsBlock := resourceBlock.GetBlock("encryption_settings")
			if encryptionSettingsBlock == nil {
				return // encryption is by default now, so this is fine
			}

			enabledAttr := encryptionSettingsBlock.GetAttribute("enabled")
			if enabledAttr != nil && enabledAttr.IsFalse() {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf(
							"Resource '%s' defines an unencrypted managed disk.",
							resourceBlock.FullName(),
						)).
						WithRange(enabledAttr.Range()).
						WithAttributeAnnotation(enabledAttr),
				)
			}

		},
	})
}
