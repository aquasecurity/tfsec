package keyvault

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AZU023",
		Service:   "keyvault",
		ShortCode: "ensure-secret-expiry",
		Documentation: rule.RuleDocumentation{
			Summary:    "Key Vault Secret should have an expiration date set",
			Impact:     "Long life secrets increase the opportunity for compromise",
			Resolution: "Set an expiry for secrets",
			Explanation: `
Expiration Date is an optional Key Vault Secret behavior and is not set by default.

Set when the resource will be become inactive.
`,
			BadExample: []string{`
resource "azurerm_key_vault_secret" "bad_example" {
  name         = "secret-sauce"
  value        = "szechuan"
  key_vault_id = azurerm_key_vault.example.id
}
`},
			GoodExample: []string{`
resource "azurerm_key_vault_secret" "good_example" {
  name            = "secret-sauce"
  value           = "szechuan"
  key_vault_id    = azurerm_key_vault.example.id
  expiration_date = "1982-12-31T00:00:00Z"
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_secret#expiration_date",
				"https://docs.microsoft.com/en-us/azure/key-vault/secrets/about-secrets",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_key_vault_secret"},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("expiration_date") {
				set.AddResult().
					WithDescription("Resource '%s' should have an expiration date set.", resourceBlock.FullName())
			}
		},
	})
}
