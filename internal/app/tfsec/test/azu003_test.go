package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AzureUnencryptedManagedDisk(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check azurerm_managed_disk with no encryption_settings",
			source: `
resource "azurerm_managed_disk" "my-disk" {
	
}`,
			mustExcludeResultCode: rules.AzureUnencryptedManagedDisk,
		},
		{
			name: "check azurerm_managed_disk with encryption disabled",
			source: `
resource "azurerm_managed_disk" "my-disk" {
	encryption_settings {
		enabled = false
	}
}`,
			mustIncludeResultCode: rules.AzureUnencryptedManagedDisk,
		},
		{
			name: "check azurerm_managed_disk with encryption enabled",
			source: `
resource "azurerm_managed_disk" "my-disk" {
	encryption_settings {
		enabled = true
	}
}`,
			mustExcludeResultCode: rules.AzureUnencryptedManagedDisk,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
