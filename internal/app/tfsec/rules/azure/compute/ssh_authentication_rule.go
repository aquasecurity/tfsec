package compute

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AZU005",
		BadExample: []string{`
 resource "azurerm_virtual_machine" "bad_example" {
 	os_profile_linux_config {
 		disable_password_authentication = false
 	}
 }`},
		GoodExample: []string{`
 resource "azurerm_virtual_machine" "good_example" {
 	os_profile_linux_config {
 		disable_password_authentication = true
 	}
 }`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine",
			"https://docs.microsoft.com/en-us/azure/virtual-machines/linux/create-ssh-keys-detailed",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_virtual_machine"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if linuxConfigBlock := resourceBlock.GetBlock("os_profile_linux_config"); linuxConfigBlock.IsNotNil() {
				if linuxConfigBlock.MissingChild("disable_password_authentication") {
					results.Add("Resource missing required attribute in os_profile_linux_config", linuxConfigBlock)
				}

				passwordAuthDisabledAttr := linuxConfigBlock.GetAttribute("disable_password_authentication")
				if passwordAuthDisabledAttr.IsNotNil() && passwordAuthDisabledAttr.IsFalse() {
					results.Add("Resource has password authentication enabled. Use SSH keys instead.", passwordAuthDisabledAttr)
				}
			}

			return results
		},
	})
}
