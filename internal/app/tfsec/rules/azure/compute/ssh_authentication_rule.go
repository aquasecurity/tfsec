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
		LegacyID:  "AZU005",
		Service:   "compute",
		ShortCode: "ssh-authentication",
		Documentation: rule.RuleDocumentation{
			Summary:    "Password authentication in use instead of SSH keys.",
			Impact:     "Passwords are potentially easier to compromise than SSH Keys",
			Resolution: "Use SSH keys for authentication",
			Explanation: `
Access to instances should be authenticated using SSH keys. Removing the option of password authentication enforces more secure methods while removing the risks inherent with passwords.
`,
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
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_virtual_machine"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if linuxConfigBlock := resourceBlock.GetBlock("os_profile_linux_config"); linuxConfigBlock.IsNotNil() {
				if linuxConfigBlock.MissingChild("disable_password_authentication") {
					set.AddResult().WithDescription("Resource '%s' missing required attribute in os_profile_linux_config", resourceBlock.FullName()).WithBlock(linuxConfigBlock)
				}

				passwordAuthDisabledAttr := linuxConfigBlock.GetAttribute("disable_password_authentication")
				if passwordAuthDisabledAttr.IsNotNil() && passwordAuthDisabledAttr.IsFalse() {
					set.AddResult().
						WithDescription("Resource '%s' has password authentication enabled. Use SSH keys instead.", resourceBlock.FullName()).
						WithAttribute(passwordAuthDisabledAttr)
				}
			}

		},
	})
}
