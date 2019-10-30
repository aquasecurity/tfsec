package checks

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
)

const AzureUnencryptedManagedDisk Code = "AZU003"

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_managed_disk"},
		CheckFunc: func(block *hcl.Block, ctx *hcl.EvalContext) []Result {

			encryptionSettingsBlock, exists := getBlock(block, "encryption_settings")
			if !exists {
				return []Result{
					NewResult(
						AzureUnencryptedManagedDisk,
						fmt.Sprintf(
							"Resource '%s' defines an unencrypted managed disk.",
							getBlockName(block),
						),
						nil,
					),
				}
			}

			if enabled, enabledRange, ok := getAttribute(encryptionSettingsBlock, ctx, "enabled"); ok && enabled.False() {
				return []Result{
					NewResult(
						AzureUnencryptedManagedDisk,
						fmt.Sprintf(
							"Resource '%s' defines an unencrypted managed disk.",
							getBlockName(block),
						),
						enabledRange,
					),
				}
			}

			return nil
		},
	})
}
