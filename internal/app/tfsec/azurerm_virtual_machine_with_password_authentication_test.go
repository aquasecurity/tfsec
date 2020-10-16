package tfsec

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks/azure"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AzureVMWithPasswordAuth(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name: "check azurerm_virtual_machine with password auth",
			source: `
resource "azurerm_virtual_machine" "my-disk" {
	os_profile_linux_config {
		disable_password_authentication = false
	}
}`,
			mustIncludeResultCode: azure.AzureVMWithPasswordAuthentication,
		},
		{
			name: "check azurerm_virtual_machine without password auth",
			source: `
resource "azurerm_virtual_machine" "my-disk" {
	os_profile_linux_config {
		disable_password_authentication = true
	}
}`,
			mustExcludeResultCode: azure.AzureVMWithPasswordAuthentication,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
