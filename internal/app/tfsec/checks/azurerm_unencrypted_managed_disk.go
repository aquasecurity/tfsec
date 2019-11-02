package checks

import (
	"fmt"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// AzureUnencryptedManagedDisk See https://github.com/liamg/tfsec#included-checks for check info
const AzureUnencryptedManagedDisk scanner.Code = "AZU003"

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AzureUnencryptedManagedDisk,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_managed_disk"},
		CheckFunc: func(check *scanner.Check, block *parser.Block) []scanner.Result {

			encryptionSettingsBlock := block.GetBlock("encryption_settings")
			if encryptionSettingsBlock == nil {
				return []scanner.Result{
					check.NewResult(
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
				return []scanner.Result{
					check.NewResult(
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
