package tfsec

import (
	"testing"

	"github.com/liamg/tfsec/internal/app/tfsec/checks"
)

func Test_AzureUnencryptedManagedDisk(t *testing.T) {

	var tests = []struct {
		name               string
		source             string
		expectedResultCode checks.Code
	}{
		{
			name: "check azurerm_managed_disk with no encryption_settings",
			source: `
resource "azurerm_managed_disk" "my-disk" {
	
}`,
			expectedResultCode: checks.AzureUnencryptedManagedDisk,
		},
		{
			name: "check azurerm_managed_disk with encryption disabled",
			source: `
resource "azurerm_managed_disk" "my-disk" {
	encryption_settings = {
		enabled = false
	}
}`,
			expectedResultCode: checks.AzureUnencryptedManagedDisk,
		},
		{
			name: "check azurerm_managed_disk with encryption enabled",
			source: `
resource "azurerm_managed_disk" "my-disk" {
	encryption_settings = {
		enabled = true
	}
}`,
			expectedResultCode: checks.None,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCodeExists(t, test.expectedResultCode, results)
		})
	}

}
