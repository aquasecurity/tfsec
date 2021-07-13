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

const AZUKeyVaultKeyExpirationDate = "AZU026"
const AZUKeyVaultKeyExpirationDateDescription = "Ensure that the expiration date is set on all keys"
const AZUKeyVaultKeyExpirationDateImpact = "Long life keys increase the attack surface when compromised"
const AZUKeyVaultKeyExpirationDateResolution = "Set an expiration date on the vault key"
const AZUKeyVaultKeyExpirationDateExplanation = `
Expiration Date is an optional Key Vault Key behavior and is not set by default.

Set when the resource will be become inactive.
`
const AZUKeyVaultKeyExpirationDateBadExample = `
resource "azurerm_key_vault_key" "bad_example" {
  name         = "generated-certificate"
  key_vault_id = azurerm_key_vault.example.id
  key_type     = "RSA"
  key_size     = 2048

  key_opts = [
    "decrypt",
    "encrypt",
    "sign",
    "unwrapKey",
    "verify",
    "wrapKey",
  ]
}
`
const AZUKeyVaultKeyExpirationDateGoodExample = `
resource "azurerm_key_vault_key" "good_example" {
  name         = "generated-certificate"
  key_vault_id = azurerm_key_vault.example.id
  key_type     = "RSA"
  key_size     = 2048
  expiration_date = "1982-12-31T00:00:00Z"

  key_opts = [
    "decrypt",
    "encrypt",
    "sign",
    "unwrapKey",
    "verify",
    "wrapKey",
  ]
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AZUKeyVaultKeyExpirationDate,
		Documentation: rule.RuleDocumentation{
			Summary:     AZUKeyVaultKeyExpirationDateDescription,
			Impact:      AZUKeyVaultKeyExpirationDateImpact,
			Resolution:  AZUKeyVaultKeyExpirationDateResolution,
			Explanation: AZUKeyVaultKeyExpirationDateExplanation,
			BadExample:  AZUKeyVaultKeyExpirationDateBadExample,
			GoodExample: AZUKeyVaultKeyExpirationDateGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_key#expiration_date",
				"https://docs.microsoft.com/en-us/powershell/module/az.keyvault/update-azkeyvaultkey?view=azps-5.8.0#example-1--modify-a-key-to-enable-it--and-set-the-expiration-date-and-tags",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_key_vault_key"},
		DefaultSeverity: severity.Medium,
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
