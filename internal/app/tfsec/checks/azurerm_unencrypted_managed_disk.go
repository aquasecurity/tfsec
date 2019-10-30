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

			encryptionSettingsVal, encryptionSettingsRange, exists := getAttribute(block, ctx, "encryption_settings");
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

			settings := encryptionSettingsVal.AsValueMap()
			if settings == nil {
				return nil
			}

			if enabled, ok := settings["enabled"]; ok && enabled.False() {
				return []Result{
					NewResult(
						AzureUnencryptedManagedDisk,
						fmt.Sprintf(
							"Resource '%s' defines an unencrypted managed disk.",
							getBlockName(block),
						),
						encryptionSettingsRange,
					),
				}
			}

			return nil
		},
	})
}
