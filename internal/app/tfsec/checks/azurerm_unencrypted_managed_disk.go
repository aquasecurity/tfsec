package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// AzureUnencryptedManagedDisk See https://github.com/liamg/tfsec#included-checks for check info
const AzureUnencryptedManagedDisk Code = "AZU003"

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_managed_disk"},
		CheckFunc: func(block *parser.Block) []Result {

			encryptionSettingsBlock := block.GetBlock("encryption_settings")
			if encryptionSettingsBlock == nil {
				return []Result{
					NewResult(
						AzureUnencryptedManagedDisk,
						fmt.Sprintf(
							"Resource '%s' defines an unencrypted managed disk.",
							block.Name(),
						),
						block.Range(),
					),
				}
			}

			enabledAttr := encryptionSettingsBlock.GetAttribute("enabled")
			if enabledAttr != nil && enabledAttr.Type() == cty.Bool && enabledAttr.Value().False() {
				return []Result{
					NewResult(
						AzureUnencryptedManagedDisk,
						fmt.Sprintf(
							"Resource '%s' defines an unencrypted managed disk.",
							block.Name(),
						),
						enabledAttr.Range(),
					),
				}
			}

			return nil
		},
	})
}
