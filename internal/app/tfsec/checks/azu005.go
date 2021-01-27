package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AzureVMWithPasswordAuthentication See https://github.com/tfsec/tfsec#included-checks for check info
const AzureVMWithPasswordAuthentication scanner.RuleCode = "AZU005"
const AzureVMWithPasswordAuthenticationDescription scanner.RuleSummary = "Password authentication in use instead of SSH keys."
const AzureVMWithPasswordAuthenticationExplanation = `
Access to instances should be authenticated using SSH keys. Removing the option of password authentication enforces more secure methods while removing the risks inherent with passwords.
`
const AzureVMWithPasswordAuthenticationBadExample = `
resource "azurerm_virtual_machine" "my-disk" {
	os_profile_linux_config {
		disable_password_authentication = false
	}
}`
const AzureVMWithPasswordAuthenticationGoodExample = `
resource "azurerm_virtual_machine" "my-disk" {
	os_profile_linux_config {
		disable_password_authentication = true
	}
}`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AzureVMWithPasswordAuthentication,
		Documentation: scanner.CheckDocumentation{
			Summary:     AzureVMWithPasswordAuthenticationDescription,
			Explanation: AzureVMWithPasswordAuthenticationExplanation,
			BadExample:  AzureVMWithPasswordAuthenticationBadExample,
			GoodExample: AzureVMWithPasswordAuthenticationGoodExample,
			Links: []string{
				"https://docs.microsoft.com/en-us/azure/virtual-machines/linux/create-ssh-keys-detailed",
				"https://www.terraform.io/docs/providers/azurerm/r/virtual_machine.html",
			},
		},
		Provider:       scanner.AzureProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_virtual_machine"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if linuxConfigBlock := block.GetBlock("os_profile_linux_config"); linuxConfigBlock != nil {
				passwordAuthDisabledAttr := linuxConfigBlock.GetAttribute("disable_password_authentication")
				if passwordAuthDisabledAttr != nil && passwordAuthDisabledAttr.Type() == cty.Bool && passwordAuthDisabledAttr.Value().False() {
					return []scanner.Result{
						check.NewResultWithValueAnnotation(
							fmt.Sprintf(
								"Resource '%s' has password authentication enabled. Use SSH keys instead.",
								block.FullName(),
							),
							passwordAuthDisabledAttr.Range(),
							passwordAuthDisabledAttr,
							scanner.SeverityError,
						),
					}
				}
			}

			return nil
		},
	})
}
