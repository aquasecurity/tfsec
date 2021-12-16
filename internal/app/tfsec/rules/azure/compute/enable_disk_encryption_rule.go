package compute

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/azure/compute"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AZU003",
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
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_managed_disk"},
		Base:           compute.CheckEnableDiskEncryption,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			encryptionSettingsBlock := resourceBlock.GetBlock("encryption_settings")
			if encryptionSettingsBlock.IsNil() {
				return // encryption is by default now, so this is fine
			}

			if encryptionSettingsBlock.MissingChild("enabled") {
				return
			}

			enabledAttr := encryptionSettingsBlock.GetAttribute("enabled")
			if enabledAttr.IsFalse() {
				results.Add("Resource defines an unencrypted managed disk.", enabledAttr)
			}

			return results
		},
	})
}
