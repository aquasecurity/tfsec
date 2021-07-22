package compute

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AzureDiablePasswordAuthentication(t *testing.T) {
	expectedCode := "azure-compute-disable-password-authentication"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "linux virtual machine with password authentication enabled fails check",
			source: `
resource "azurerm_linux_virtual_machine" "bad_linux_example" {
  name                            = "bad-linux-machine"
  resource_group_name             = azurerm_resource_group.example.name
  location                        = azurerm_resource_group.example.location
  size                            = "Standard_F2"
  admin_username                  = "adminuser"
  admin_password                  = "somePassword"
  disable_password_authentication = false
}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "virtual machine with password authentication enabled fails check",
			source: `
resource "azurerm_virtual_machine" "bad_example" {
	name                            = "bad-linux-machine"
	resource_group_name             = azurerm_resource_group.example.name
	location                        = azurerm_resource_group.example.location
	size                            = "Standard_F2"
	admin_username                  = "adminuser"
	admin_password                  = "somePassword"

	os_profile {
		computer_name  = "hostname"
		admin_username = "testadmin"
		admin_password = "Password1234!"
	}

	os_profile_linux_config {
		disable_password_authentication = false
	}
}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "virtual machine with password authentication disabled passes check",
			source: `
resource "azurerm_virtual_machine" "good_example" {
	name                            = "good-linux-machine"
	resource_group_name             = azurerm_resource_group.example.name
	location                        = azurerm_resource_group.example.location
	size                            = "Standard_F2"
	admin_username                  = "adminuser"

	
	os_profile_linux_config {
		ssh_keys = [{
			key_data = file("~/.ssh/id_rsa.pub")
			path = "~/.ssh/id_rsa.pub"
		}]

		disable_password_authentication = true
	}
}
`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "linux virtual machine with password authentication disable passes check",
			source: `
resource "azurerm_linux_virtual_machine" "good_linux_example" {
  name                            = "good-linux-machine"
  resource_group_name             = azurerm_resource_group.example.name
  location                        = azurerm_resource_group.example.location
  size                            = "Standard_F2"
  admin_username                  = "adminuser"
  admin_password                  = "somePassword"
  
  admin_ssh_key {
    username   = "adminuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }
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
