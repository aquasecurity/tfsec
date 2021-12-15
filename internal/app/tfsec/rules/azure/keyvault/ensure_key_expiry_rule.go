package keyvault

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
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
			"https://docs.microsoft.com/en-us/powershell/module/az.keyvault/update-azkeyvaultkey?view=azps-5.8.0#example-1--modify-a-key-to-enable-it--and-set-the-expiration-date-and-tags",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_key_vault_key"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("expiration_date") {
				results.Add("Resource should have an expiration date set.", resourceBlock)
			}
			return results
		},
	})
}
