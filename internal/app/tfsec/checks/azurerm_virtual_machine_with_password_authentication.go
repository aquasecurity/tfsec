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

			if linuxConfigBlock, exists := getBlock(block, "os_profile_linux_config"); exists {
				if passwordAuthDisabled, disabledRange, found := getAttribute(linuxConfigBlock, ctx, "disable_password_authentication"); found && passwordAuthDisabled.False() {
					return []Result{
						NewResult(
							AzureVMWithPasswordAuthentication,
							fmt.Sprintf(
								"Resource '%s' has password authentication enabled. Use SSH keys instead.",
								getBlockName(block),
							),
							disabledRange,
						),
					}
				}
			}

			return nil
		},
	})
}
