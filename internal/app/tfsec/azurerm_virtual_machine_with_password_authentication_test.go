package tfsec

import (
	"testing"

	"github.com/liamg/tfsec/internal/app/tfsec/checks"
)

func Test_AzureVMWithPasswordAuth(t *testing.T) {

	var tests = []struct {
		name               string
		source             string
		expectedResultCode checks.Code
	}{
		{
			name: "check azurerm_virtual_machine with password auth",
			source: `
resource "azurerm_virtual_machine" "my-disk" {
	os_profile_linux_config = {
		disable_password_authentication = false
	}
}`,
			expectedResultCode: checks.AzureVMWithPasswordAuthentication,
		},
		{
			name: "check azurerm_virtual_machine without password auth",
			source: `
resource "azurerm_virtual_machine" "my-disk" {
	os_profile_linux_config = {
		disable_password_authentication = true
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
