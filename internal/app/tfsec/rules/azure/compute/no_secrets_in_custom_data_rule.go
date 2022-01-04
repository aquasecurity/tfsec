package compute

import (
	"github.com/aquasecurity/defsec/rules/azure/compute"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
 resource "azurerm_virtual_machine" "bad_example" {
 	name = "bad_example"
	os_profile_linux_config {
		disable_password_authentication = false
	}
	os_profile {
		custom_data =<<EOF
			export DATABASE_PASSWORD=\"SomeSortOfPassword\"
			EOF
	}
 }
 `},
		GoodExample: []string{`
 resource "azurerm_virtual_machine" "good_example" {
 	name = "good_example"
	os_profile_linux_config {
		disable_password_authentication = false
	}
	os_profile {
		custom_data =<<EOF
			export GREETING="Hello there"
			EOF
	}
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine#custom_data",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_virtual_machine", "azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine"},
		Base:           compute.CheckNoSecretsInCustomData,
	})
}
