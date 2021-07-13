package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const AZUKeyVaultSecretExpirationDate = "AZU023"
const AZUKeyVaultSecretExpirationDateDescription = "Key Vault Secret should have an expiration date set"
const AZUKeyVaultSecretExpirationDateImpact = "Long life secrets increase the opportunity for compromise"
const AZUKeyVaultSecretExpirationDateResolution = "Set an expiry for secrets"
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
	scanner.RegisterCheckRule(rule.Rule{
		ID: AZUKeyVaultSecretExpirationDate,
		Documentation: rule.RuleDocumentation{
			Summary:     AZUKeyVaultSecretExpirationDateDescription,
			Impact:      AZUKeyVaultSecretExpirationDateImpact,
			Resolution:  AZUKeyVaultSecretExpirationDateResolution,
			Explanation: AZUKeyVaultSecretExpirationDateExplanation,
			BadExample:  AZUKeyVaultSecretExpirationDateBadExample,
			GoodExample: AZUKeyVaultSecretExpirationDateGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_secret#expiration_date",
				"https://docs.microsoft.com/en-us/azure/key-vault/secrets/about-secrets",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_key_vault_secret"},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if resourceBlock.MissingChild("expiration_date") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' should have an expiration date set.", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
			}
		},
	})
}
