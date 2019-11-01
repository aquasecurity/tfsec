package checks

import (
	"fmt"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
	"github.com/zclconf/go-cty/cty"
)

// AzureUnencryptedDataLakeStore See https://github.com/liamg/tfsec#included-checks for check info
const AzureUnencryptedDataLakeStore Code = "AZU004"

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_data_lake_store"},
		CheckFunc: func(block *parser.Block) []Result {

			encryptionStateAttr := block.GetAttribute("encryption_state")
			if encryptionStateAttr != nil && encryptionStateAttr.Type() == cty.String && encryptionStateAttr.Value().AsString() == "Disabled" {
				return []Result{
					NewResult(
						AzureUnencryptedDataLakeStore,
						fmt.Sprintf(
							"Resource '%s' defines an unencrypted data lake store.",
							block.Name(),
						),
						encryptionStateAttr.Range(),
					),
				}
			}

			return nil
		},
	})
}
