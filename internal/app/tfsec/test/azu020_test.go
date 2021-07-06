package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AZUKeyVaultNetworkAcl(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check fails when no network acl block is provided",
			source: `
resource "azurerm_key_vault" "bad_example" {
    name                        = "examplekeyvault"
    location                    = azurerm_resource_group.bad_example.location
    enabled_for_disk_encryption = true
    soft_delete_retention_days  = 7
    purge_protection_enabled    = false
}
`,
			mustIncludeResultCode: rules.AZUKeyVaultNetworkAcl,
		}, {
			name: "check fails when network acl block is provided with default action as allow",
			source: `
resource "azurerm_key_vault" "bad_example" {
    name                        = "examplekeyvault"
    location                    = azurerm_resource_group.bad_example.location
    enabled_for_disk_encryption = true
    soft_delete_retention_days  = 7
    purge_protection_enabled    = false

    network_acls {
        bypass = "AzureServices"
        default_action = "Allow"
    }
}
`,
			mustIncludeResultCode: rules.AZUKeyVaultNetworkAcl,
		},
		{
			name: "check passes when network acl is provided and default action is deny",
			source: `
resource "azurerm_key_vault" "good_example" {
    name                        = "examplekeyvault"
    location                    = azurerm_resource_group.good_example.location
    enabled_for_disk_encryption = true
    soft_delete_retention_days  = 7
    purge_protection_enabled    = false

    network_acls {
        bypass = "AzureServices"
        default_action = "Deny"
    }
}
`,
			mustExcludeResultCode: rules.AZUKeyVaultNetworkAcl,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
