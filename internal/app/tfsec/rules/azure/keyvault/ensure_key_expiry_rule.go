package keyvault

import (
	"github.com/aquasecurity/defsec/rules/azure/keyvault"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AZU026",
		BadExample: []string{`
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
 `},
		GoodExample: []string{`
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
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_key#expiration_date",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_key_vault_key"},
		Base:           keyvault.CheckEnsureKeyExpiry,
	})
}
