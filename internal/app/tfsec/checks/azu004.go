package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AzureUnencryptedDataLakeStore See https://github.com/tfsec/tfsec#included-checks for check info
const AzureUnencryptedDataLakeStore scanner.RuleCode = "AZU004"
const AzureUnencryptedDataLakeStoreDescription scanner.RuleSummary = "Unencrypted data lake storage."
const AzureUnencryptedDataLakeStoreExplanation = `
Datalake storage encryption defaults to Enabled, it shouldn't be overridden to Disabled.
`
const AzureUnencryptedDataLakeStoreBadExample = `
resource "azurerm_data_lake_store" "my-lake-store" {
	encryption_state = "Disabled"
}`
const AzureUnencryptedDataLakeStoreGoodExample = `
resource "azurerm_data_lake_store" "my-lake-store" {
	encryption_state = "Enabled"
}`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AzureUnencryptedDataLakeStore,
		Documentation: scanner.CheckDocumentation{
			Summary:     AzureUnencryptedDataLakeStoreDescription,
			Explanation: AzureUnencryptedDataLakeStoreExplanation,
			BadExample:  AzureUnencryptedDataLakeStoreBadExample,
			GoodExample: AzureUnencryptedDataLakeStoreGoodExample,
			Links: []string{
				"https://docs.microsoft.com/en-us/azure/data-lake-store/data-lake-store-security-overview",
				"https://www.terraform.io/docs/providers/azurerm/r/data_lake_store.html",
			},
		},
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
							block.FullName(),
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
