package keyvault

import (
	"github.com/aquasecurity/defsec/rules/azure/keyvault"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AZU022",
		BadExample: []string{`
 resource "azurerm_key_vault" "example" {
 }

 resource "azurerm_key_vault_secret" "bad_example" {
   name         = "secret-sauce"
   value        = "szechuan"
   key_vault_id = azurerm_key_vault.example.id
 }
 `},
		GoodExample: []string{`
resource "azurerm_key_vault" "example" {
}

 resource "azurerm_key_vault_secret" "good_example" {
   name         = "secret-sauce"
   value        = "szechuan"
   key_vault_id = azurerm_key_vault.example.id
   content_type = "password"
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_secret#content_type",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_key_vault_secret"},
		Base:           keyvault.CheckContentTypeForSecret,
	})
}
