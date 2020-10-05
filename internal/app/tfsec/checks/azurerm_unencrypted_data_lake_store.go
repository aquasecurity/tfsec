package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/zclconf/go-cty/cty"
)

// AzureUnencryptedDataLakeStore See https://github.com/tfsec/tfsec#included-checks for check info
const AzureUnencryptedDataLakeStore scanner.RuleID = "AZU004"
const AzureUnencryptedDataLakeStoreDescription scanner.RuleDescription = "Unencrypted data lake store."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AzureUnencryptedDataLakeStore,
		Description:    AzureUnencryptedDataLakeStoreDescription,
		Provider:       scanner.AzureProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_data_lake_store"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			encryptionStateAttr := block.GetAttribute("encryption_state")
			if encryptionStateAttr != nil && encryptionStateAttr.Type() == cty.String && encryptionStateAttr.Value().AsString() == "Disabled" {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf(
							"Resource '%s' defines an unencrypted data lake store.",
							block.Name(),
						),
						encryptionStateAttr.Range(),
						encryptionStateAttr,
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
