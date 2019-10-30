package checks

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

// AzureUnencryptedDataLakeStore See https://github.com/liamg/tfsec#included-checks for check info
const AzureUnencryptedDataLakeStore Code = "AZU004"

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_data_lake_store"},
		CheckFunc: func(block *hcl.Block, ctx *hcl.EvalContext) []Result {

			if encryptionStateVal, encryptionStateRange, exists := getAttribute(block, ctx, "encryption_state"); exists && encryptionStateVal.Type() == cty.String && encryptionStateVal.AsString() == "Disabled" {
				return []Result{
					NewResult(
						AzureUnencryptedDataLakeStore,
						fmt.Sprintf(
							"Resource '%s' defines an unencrypted data lake store.",
							getBlockName(block),
						),
						encryptionStateRange,
					),
				}
			}

			return nil
		},
	})
}
