package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AzureUnencryptedManagedDisk See https://github.com/tfsec/tfsec#included-checks for check info
const AzureUnencryptedManagedDisk scanner.RuleID = "AZU003"
const AzureUnencryptedManagedDiskDescription scanner.RuleDescription = "Unencrypted managed disk."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AzureUnencryptedManagedDisk,
		Description:    AzureUnencryptedManagedDiskDescription,
		Provider:       scanner.AzureProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_managed_disk"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			encryptionSettingsBlock := block.GetBlock("encryption_settings")
			if encryptionSettingsBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf(
							"Resource '%s' defines an unencrypted managed disk.",
							block.Name(),
						),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			enabledAttr := encryptionSettingsBlock.GetAttribute("enabled")
			if enabledAttr != nil && enabledAttr.Type() == cty.Bool && enabledAttr.Value().False() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf(
							"Resource '%s' defines an unencrypted managed disk.",
							block.Name(),
						),
						enabledAttr.Range(),
						enabledAttr,
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
