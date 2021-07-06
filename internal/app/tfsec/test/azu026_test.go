package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AZUKeyVaultKeyExpirationDate(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check if expiration_date is not set, check fails",
			source: `
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
`,
			mustIncludeResultCode: rules.AZUKeyVaultKeyExpirationDate,
		},
		{
			name: "check if expiration_date is set, check passes",
			source: `
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
`,
			mustExcludeResultCode: rules.AZUKeyVaultKeyExpirationDate,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
