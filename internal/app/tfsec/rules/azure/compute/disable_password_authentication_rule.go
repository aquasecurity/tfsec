package compute

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		Service:   "compute",
		ShortCode: "disable-password-authentication",
		Documentation: rule.RuleDocumentation{
			Summary:     "Password authentication should be disabled on Azure virtual machines",
			Explanation: `Access to virtual machines should be authenticated using SSH keys. Removing the option of password authentication enforces more secure methods while removing the risks inherent with passwords.`,
			Impact:      "Using password authentication is less secure that ssh keys may result in compromised servers",
			Resolution:  "Use ssh authentication for virtual machines",
			BadExample: []string{`
resource "azurerm_linux_virtual_machine" "bad_linux_example" {
  name                            = "bad-linux-machine"
  resource_group_name             = azurerm_resource_group.example.name
  location                        = azurerm_resource_group.example.location
  size                            = "Standard_F2"
  admin_username                  = "adminuser"
  admin_password                  = "somePassword"
  disable_password_authentication = false
}

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
`},
			GoodExample: []string{`
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
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_virtual_machine#disable_password_authentication",
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine#disable_password_authentication",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_linux_virtual_machine", "azurerm_virtual_machine"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			workingBlock := resourceBlock
			if resourceBlock.TypeLabel() == "azurerm_virtual_machine" {
				if resourceBlock.HasChild("os_profile_linux_config") {
					workingBlock = resourceBlock.GetBlock("os_profile_linux_config")
				}
			}

			if workingBlock.MissingChild("disable_password_authentication") {
				return
			}

			passwordAuthAttr := workingBlock.GetAttribute("disable_password_authentication")
			if passwordAuthAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' has password authentication enabled.", resourceBlock.FullName()).WithAttribute(passwordAuthAttr)
			}
		},
	})
}
