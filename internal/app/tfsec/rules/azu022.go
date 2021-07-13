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

const AZUKeyVaultSecretContentType = "AZU022"
const AZUKeyVaultSecretContentTypeDescription = "Key vault Secret should have a content type set"
const AZUKeyVaultSecretContentTypeImpact = "The secret's type is unclear without a content type"
const AZUKeyVaultSecretContentTypeResolution = "Provide content type for secrets to aid interpretation on retrieval"
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
	scanner.RegisterCheckRule(rule.Rule{
		ID: AZUKeyVaultSecretContentType,
		Documentation: rule.RuleDocumentation{
			Summary:     AZUKeyVaultSecretContentTypeDescription,
			Impact:      AZUKeyVaultSecretContentTypeImpact,
			Resolution:  AZUKeyVaultSecretContentTypeResolution,
			Explanation: AZUKeyVaultSecretContentTypeExplanation,
			BadExample:  AZUKeyVaultSecretContentTypeBadExample,
			GoodExample: AZUKeyVaultSecretContentTypeGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_secret#content_type",
				"https://docs.microsoft.com/en-us/azure/key-vault/secrets/about-secrets",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_key_vault_secret"},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if resourceBlock.MissingChild("content_type") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' should have a content type set.", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
			}
		},
	})
}
