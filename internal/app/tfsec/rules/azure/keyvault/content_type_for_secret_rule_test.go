package keyvault

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AZUKeyVaultSecretContentType(t *testing.T) {
	expectedCode := "azure-keyvault-content-type-for-secret"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check if content_type is not set, check fails",
			source: `
 resource "azurerm_key_vault_secret" "bad_example" {
   name         = "secret-sauce"
   value        = "szechuan"
   key_vault_id = azurerm_key_vault.example.id
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check if content_type is set, check passes",
			source: `
 resource "azurerm_key_vault_secret" "good_example" {
   name         = "secret-sauce"
   value        = "szechuan"
   key_vault_id = azurerm_key_vault.example.id
   content_type = "password"
 }
 `,
			mustExcludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
