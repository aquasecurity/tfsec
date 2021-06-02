package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AZUDataFactoryPublicNetwork(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check if public_network_enabled not set, check fails",
			source: `
resource "azurerm_data_factory" "bad_example" {
  name                = "example"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
}
`,
			mustIncludeResultCode: rules.AZUDataFactoryPublicNetwork,
		},
		{
			name: "check if public_network_enabled is set to false, check passes",
			source: `
resource "azurerm_data_factory" "good_example" {
  name                = "example"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  public_network_enabled = false
}
`,
			mustExcludeResultCode: rules.AZUDataFactoryPublicNetwork,
		},
		{
			name: "check if public_network_enabled is set to true, check fails",
			source: `
resource "azurerm_data_factory" "bad_example" {
  name                = "example"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  public_network_enabled = true
}
`,
			mustIncludeResultCode: rules.AZUDataFactoryPublicNetwork,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
