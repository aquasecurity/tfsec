package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AZUMinTLSForStorageAccountsSet scanner.RuleCode = "AZU015"
const AZUMinTLSForStorageAccountsSetDescription scanner.RuleSummary = "The minimum TLS version for Storage Accounts should be TLS1_2"
const AZUMinTLSForStorageAccountsSetExplanation = `
Azure Storage currently supports three versions of the TLS protocol: 1.0, 1.1, and 1.2. 

Azure Storage uses TLS 1.2 on public HTTPS endpoints, but TLS 1.0 and TLS 1.1 are still supported for backward compatibility.

This check will warn if the minimum TLS is not set to TLS1_2.
`
const AZUMinTLSForStorageAccountsSetBadExample = `
resource "azurerm_storage_account" "bad_example" {
  name                     = "storageaccountname"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
}
`
const AZUMinTLSForStorageAccountsSetGoodExample = `
resource "azurerm_storage_account" "good_example" {
  name                     = "storageaccountname"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  min_tls_version          = "TLS1_2"
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AZUMinTLSForStorageAccountsSet,
		Documentation: scanner.CheckDocumentation{
			Summary:     AZUMinTLSForStorageAccountsSetDescription,
			Explanation: AZUMinTLSForStorageAccountsSetExplanation,
			BadExample:  AZUMinTLSForStorageAccountsSetBadExample,
			GoodExample: AZUMinTLSForStorageAccountsSetGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#min_tls_version",
				"https://docs.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version",
			},
		},
		Provider:       scanner.AzureProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_storage_account"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.MissingChild("min_tls_version") || block.GetAttribute("min_tls_version").IsNone("TLS1_2") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' should have the min tls version set to TLS1_2 .", block.FullName()),
						block.Range(),
						scanner.SeverityWarning,
					),
				}
			}

			return nil
		},
	})
}
