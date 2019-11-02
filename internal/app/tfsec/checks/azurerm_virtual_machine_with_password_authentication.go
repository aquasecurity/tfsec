package checks

import (
	"fmt"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// AzureVMWithPasswordAuthentication See https://github.com/liamg/tfsec#included-checks for check info
const AzureVMWithPasswordAuthentication scanner.Code = "AZU005"

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AzureVMWithPasswordAuthentication,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_virtual_machine"},
		CheckFunc: func(check *scanner.Check, block *parser.Block) []scanner.Result {

			if linuxConfigBlock := block.GetBlock("os_profile_linux_config"); linuxConfigBlock != nil {
				passwordAuthDisabledAttr := linuxConfigBlock.GetAttribute("disable_password_authentication")
				if passwordAuthDisabledAttr != nil && passwordAuthDisabledAttr.Type() == cty.Bool && passwordAuthDisabledAttr.Value().False() {
					return []scanner.Result{
						check.NewResult(
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
