package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AZUKeyVaultSecretContentType scanner.RuleCode = "AZU022"
const AZUKeyVaultSecretContentTypeDescription scanner.RuleSummary = "Key vault Secret should have a content type set"
const AZUKeyVaultSecretContentTypeExplanation = `
Content Type is an optional Key Vault Secret behavior and is not enabled by default.

Clients may specify the content type of a secret to assist in interpreting the secret data when it's retrieved. The maximum length of this field is 255 characters. There are no pre-defined values. The suggested usage is as a hint for interpreting the secret data.
`
const AZUKeyVaultSecretContentTypeBadExample = `
resource "azurerm_key_vault_secret" "bad_example" {
  name         = "secret-sauce"
  value        = "szechuan"
  key_vault_id = azurerm_key_vault.example.id
}
`
const AZUKeyVaultSecretContentTypeGoodExample = `
resource "azurerm_key_vault_secret" "good_example" {
  name         = "secret-sauce"
  value        = "szechuan"
  key_vault_id = azurerm_key_vault.example.id
  content_type = "password"
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AZUKeyVaultSecretContentType,
		Documentation: scanner.CheckDocumentation{
			Summary:     AZUKeyVaultSecretContentTypeDescription,
			Explanation: AZUKeyVaultSecretContentTypeExplanation,
			BadExample:  AZUKeyVaultSecretContentTypeBadExample,
			GoodExample: AZUKeyVaultSecretContentTypeGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_secret#content_type",
				"https://docs.microsoft.com/en-us/azure/key-vault/secrets/about-secrets",
			},
		},
		Provider:       scanner.AzureProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_key_vault_secret"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.MissingChild("content_type") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' should have a content type set.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}
			return nil
		},
	})
}
