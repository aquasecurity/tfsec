package checks

import (
	"fmt"
	"github.com/hashicorp/hcl/v2"
)

const AzureVMWithPasswordAuthentication Code = "AZU005"

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_virtual_machine"},
		CheckFunc: func(block *hcl.Block, ctx *hcl.EvalContext) []Result {

			if linuxConfigVal, linuxConfigRange, exists := getAttribute(block, ctx, "os_profile_linux_config"); exists {
				valueMap := linuxConfigVal.AsValueMap()
				if passwordAuthDisabled, found := valueMap["disable_password_authentication"]; found && passwordAuthDisabled.False() {
					return []Result{
						NewResult(
							AzureVMWithPasswordAuthentication,
							fmt.Sprintf(
								"Resource '%s' has password authentication enabled. Use SSH keys instead.",
								getBlockName(block),
							),
							linuxConfigRange,
						),
					}
				}
			}

			return nil
		},
	})
}
