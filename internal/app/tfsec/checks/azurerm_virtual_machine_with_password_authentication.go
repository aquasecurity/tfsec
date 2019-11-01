package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// AzureVMWithPasswordAuthentication See https://github.com/liamg/tfsec#included-checks for check info
const AzureVMWithPasswordAuthentication Code = "AZU005"

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_virtual_machine"},
		CheckFunc: func(block *parser.Block) []Result {

			if linuxConfigBlock := block.GetBlock("os_profile_linux_config"); linuxConfigBlock != nil {
				passwordAuthDisabledAttr := linuxConfigBlock.GetAttribute("disable_password_authentication")
				if passwordAuthDisabledAttr != nil && passwordAuthDisabledAttr.Type() == cty.Bool && passwordAuthDisabledAttr.Value().False() {
					return []Result{
						NewResult(
							AzureVMWithPasswordAuthentication,
							fmt.Sprintf(
								"Resource '%s' has password authentication enabled. Use SSH keys instead.",
								block.Name(),
							),
							passwordAuthDisabledAttr.Range(),
						),
					}
				}
			}

			return nil
		},
	})
}
