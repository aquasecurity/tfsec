package compute

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AzureVMWithPasswordAuth(t *testing.T) {
	expectedCode := "azure-compute-ssh-authentication"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check azurerm_virtual_machine with password auth",
			source: `
 resource "azurerm_virtual_machine" "my-disk" {
 	os_profile_linux_config {
 		disable_password_authentication = false
 	}
 }`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check azurerm_virtual_machine without password auth",
			source: `
 resource "azurerm_virtual_machine" "my-disk" {
 	os_profile_linux_config {
 		disable_password_authentication = true
 	}
 }`,
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
