package tfsec

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
)

func Test_AzureUnencryptedManagedDisk(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name: "check azurerm_managed_disk with no encryption_settings",
			source: `
resource "azurerm_managed_disk" "my-disk" {
	
}`,
			mustIncludeResultCode: checks.AzureUnencryptedManagedDisk,
		},
		{
			name: "check azurerm_managed_disk with encryption disabled",
			source: `
resource "azurerm_managed_disk" "my-disk" {
	encryption_settings {
		enabled = false
	}
}`,
			mustIncludeResultCode: checks.AzureUnencryptedManagedDisk,
		},
		{
			name: "check azurerm_managed_disk with encryption enabled",
			source: `
resource "azurerm_managed_disk" "my-disk" {
	encryption_settings {
		enabled = true
	}
}`,
			mustExcludeResultCode: checks.AzureUnencryptedManagedDisk,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
