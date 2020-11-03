package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
	"github.com/zclconf/go-cty/cty"
)

const AZUStorageAccountHTTPSenabled scanner.RuleCode = "AZU010"
const AZUStorageAccountHTTPSenabledDescription scanner.RuleSummary = "Ensure HTTPS is enabled on Azure Storage Account"
const AZUStorageAccountHTTPSenabledExplanation = `
Requiring HTTPS in Storage Account helps to minimize the risk of eavesdropping.
`
const AZUStorageAccountHTTPSenabledBadExample = `
resource "azurerm_storage_account" "my-storage-account" {
	enable_https_traffic_only = false
}
`
const AZUStorageAccountHTTPSenabledGoodExample = `
resource "azurerm_storage_account" "my-storage-account" {
	enable_https_traffic_only = true
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AZUStorageAccountHTTPSenabled,
		Documentation: scanner.CheckDocumentation{
			Summary:     AZUStorageAccountHTTPSenabledDescription,
			Explanation: AZUStorageAccountHTTPSenabledExplanation,
			BadExample:  AZUStorageAccountHTTPSenabledBadExample,
			GoodExample: AZUStorageAccountHTTPSenabledGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account",
				"https://docs.microsoft.com/en-us/azure/storage/blobs/security-recommendations",
			},
		},
		Provider:       scanner.AzureProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_storage_account", "enable_https_traffic_only"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			enabledAttr := block.GetAttribute("enable_https_traffic_only")
			if enabledAttr != nil && enabledAttr.Type() == cty.Bool && enabledAttr.Value().False() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf(
							"Resource '%s' enable_https_traffic_only disabled.",
							block.FullName(),
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
