package keyvault

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AZU023",
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
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_key_vault_secret"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("expiration_date") {
				results.Add("Resource should have an expiration date set.", resourceBlock)
			}
			return results
		},
	})
}
