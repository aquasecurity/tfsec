package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AZUKeyVaultSecretExpirationDate(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check if expiration_date is not set, check fails",
			source: `
resource "azurerm_key_vault_secret" "bad_example" {
  name         = "secret-sauce"
  value        = "szechuan"
  key_vault_id = azurerm_key_vault.example.id
}
`,
			mustIncludeResultCode: rules.AZUKeyVaultSecretExpirationDate,
		},
		{
			name: "check if expiration_date is set, check passes",
			source: `
resource "azurerm_key_vault_secret" "good_example" {
  name            = "secret-sauce"
  value        	  = "szechuan"
  key_vault_id    = azurerm_key_vault.example.id
  expiration_date = "1982-12-31T00:00:00Z"
}
`,
			mustExcludeResultCode: rules.AZUKeyVaultSecretExpirationDate,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
