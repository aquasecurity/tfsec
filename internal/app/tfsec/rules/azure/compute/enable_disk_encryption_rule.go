package compute

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
		LegacyID:  "AZU003",
		Service:   "compute",
		ShortCode: "enable-disk-encryption",
		Documentation: rule.RuleDocumentation{
			Summary:    "Enable disk encryption on managed disk",
			Impact:     "Data could be read if compromised",
			Resolution: "Enable encryption on managed disks",
			Explanation: `
Manage disks should be encrypted at rest. When specifying the <code>encryption_settings</code> block, the enabled attribute should be set to <code>true</code>.
`,
			BadExample: []string{`
resource "azurerm_managed_disk" "bad_example" {
	encryption_settings {
		enabled = false
	}
}`},
			GoodExample: []string{`
resource "azurerm_managed_disk" "good_example" {
	encryption_settings {
		enabled = true
	}
}`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/managed_disk",
				"https://docs.microsoft.com/en-us/azure/virtual-machines/linux/disk-encryption",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_managed_disk"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {
			encryptionSettingsBlock := resourceBlock.GetBlock("encryption_settings")
			if encryptionSettingsBlock.IsNil() {
				return // encryption is by default now, so this is fine
			}

			if encryptionSettingsBlock.MissingChild("enabled") {
				return
			}

			enabledAttr := encryptionSettingsBlock.GetAttribute("enabled")
			if enabledAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' defines an unencrypted managed disk.", resourceBlock.FullName()).
					WithAttribute(enabledAttr)
			}

		},
	})
}
