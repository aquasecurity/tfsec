package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AzureVMWithPasswordAuth(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check azurerm_virtual_machine with password auth",
			source: `
resource "azurerm_virtual_machine" "my-disk" {
	os_profile_linux_config {
		disable_password_authentication = false
	}
}`,
			mustIncludeResultCode: checks.AzureVMWithPasswordAuthentication,
		},
		{
			name: "check azurerm_virtual_machine without password auth",
			source: `
resource "azurerm_virtual_machine" "my-disk" {
	os_profile_linux_config {
		disable_password_authentication = true
	}
}`,
			mustExcludeResultCode: checks.AzureVMWithPasswordAuthentication,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
