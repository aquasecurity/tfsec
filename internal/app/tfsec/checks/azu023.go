package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AZUKeyVaultSecretExpirationDate scanner.RuleCode = "AZU023"
const AZUKeyVaultSecretExpirationDateDescription scanner.RuleSummary = "Key Vault Secret should have an expiration date set"
const AZUKeyVaultSecretExpirationDateExplanation = `
Expiration Date is an optional Key Vault Secret behavior and is not set by default.

Set when the resource will be become inactive.
`
const AZUKeyVaultSecretExpirationDateBadExample = `
resource "azurerm_key_vault_secret" "bad_example" {
  name         = "secret-sauce"
  value        = "szechuan"
  key_vault_id = azurerm_key_vault.example.id
}
`
const AZUKeyVaultSecretExpirationDateGoodExample = `
resource "azurerm_key_vault_secret" "good_example" {
  name            = "secret-sauce"
  value           = "szechuan"
  key_vault_id    = azurerm_key_vault.example.id
  expiration_date = "1982-12-31T00:00:00Z"
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AZUKeyVaultSecretExpirationDate,
		Documentation: scanner.CheckDocumentation{
			Summary:     AZUKeyVaultSecretExpirationDateDescription,
			Explanation: AZUKeyVaultSecretExpirationDateExplanation,
			BadExample:  AZUKeyVaultSecretExpirationDateBadExample,
			GoodExample: AZUKeyVaultSecretExpirationDateGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_secret#expiration_date",
				"https://docs.microsoft.com/en-us/azure/key-vault/secrets/about-secrets",
			},
		},
		Provider:       scanner.AzureProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_key_vault_secret"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.MissingChild("expiration_date") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' should have an expiration date set.", block.FullName()),
						block.Range(),
						scanner.SeverityWarning,
					),
				}
			}
			return nil
		},
	})
}
