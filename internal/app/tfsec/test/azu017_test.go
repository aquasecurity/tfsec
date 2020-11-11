package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AZUSSHAccessNotAllowedFromInternet(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check ssh access from * causes a failure",
			source: `
resource "azurerm_network_security_rule" "bad_example" {
     name                        = "bad_example_security_rule"
     direction                   = "Inbound"
     access                      = "Allow"
     protocol                    = "TCP"
     source_port_range           = "*"
     destination_port_range      = ["22"]
     source_address_prefix       = "*"
     destination_address_prefix  = "*"
}
`,
			mustIncludeResultCode: checks.AZUSSHAccessNotAllowedFromInternet,
		},
		{
			name: "check ssh access from 0.0.0.0 causes a failure",
			source: `
resource "azurerm_network_security_rule" "bad_example" {
     name                        = "bad_example_security_rule"
     direction                   = "Inbound"
     access                      = "Allow"
     protocol                    = "TCP"
     source_port_range           = "0.0.0.0"
     destination_port_range      = ["22"]
     source_address_prefix       = "*"
     destination_address_prefix  = "*"
}
`,
			mustIncludeResultCode: checks.AZUSSHAccessNotAllowedFromInternet,
		},
		{
			name: "check ssh access from /0 causes a failure",
			source: `
resource "azurerm_network_security_rule" "bad_example" {
     name                        = "bad_example_security_rule"
     direction                   = "Inbound"
     access                      = "Allow"
     protocol                    = "TCP"
     source_port_range           = "/0"
     destination_port_range      = ["22"]
     source_address_prefix       = "*"
     destination_address_prefix  = "*"
}
`,
			mustIncludeResultCode: checks.AZUSSHAccessNotAllowedFromInternet,
		},
		{
			name: "check ssh access from internet causes a failure",
			source: `
resource "azurerm_network_security_rule" "bad_example" {
     name                        = "bad_example_security_rule"
     direction                   = "Inbound"
     access                      = "Allow"
     protocol                    = "TCP"
     source_port_range           = "internet"
     destination_port_range      = ["22"]
     source_address_prefix       = "*"
     destination_address_prefix  = "*"
}
`,
			mustIncludeResultCode: checks.AZUSSHAccessNotAllowedFromInternet,
		},
		{
			name: "check ssh access from internet causes a failure",
			source: `
resource "azurerm_network_security_rule" "bad_example" {
     name                        = "bad_example_security_rule"
     direction                   = "Inbound"
     access                      = "Allow"
     protocol                    = "TCP"
     source_port_range           = "any"
     destination_port_range      = ["22"]
     source_address_prefix       = "*"
     destination_address_prefix  = "*"
}
`,
			mustIncludeResultCode: checks.AZUSSHAccessNotAllowedFromInternet,
		},
		{
			name: "check ssh access from * causes a failure on security group",
			source: `
resource "azurerm_network_security_group" "example" {
  name                = "tf-appsecuritygroup"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  
  security_rule {
	 source_port_range           = "any"
     destination_port_range      = ["22", "80", "443"]
     source_address_prefix       = "*"
     destination_address_prefix  = "*"
  }
}
`,
			mustIncludeResultCode: checks.AZUSSHAccessNotAllowedFromInternet,
		},
		{
			name: "check ssh access from multiple security rules causes a failure on security group",
			source: `
resource "azurerm_network_security_group" "example" {
  name                = "tf-appsecuritygroup"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  
  security_rule {
	 source_port_range           = "any"
     destination_port_range      = ["22", "80", "443"]
     source_address_prefix       = "82.102.32.32"
     destination_address_prefix  = "*"
  }

  security_rule {
	 source_port_range           = "any"
     destination_port_range      = ["22", "80", "443"]
     source_address_prefix       = "internet"
     destination_address_prefix  = "*"
  }
}
`,
			mustIncludeResultCode: checks.AZUSSHAccessNotAllowedFromInternet,
		},
		{
			name: "check ssh is acceptable from a specific source",
			source: `
resource "azurerm_network_security_rule" "good_example" {
     name                        = "good_example_security_rule"
     direction                   = "Inbound"
     access                      = "Allow"
     protocol                    = "TCP"
     source_port_range           = "*"
     destination_port_range      = ["22"]
     source_address_prefix       = "82.102.23.23"
     destination_address_prefix  = "*"
}
`,
			mustExcludeResultCode: checks.AZUSSHAccessNotAllowedFromInternet,
		},
		{
			name: "check ssh is acceptable from a specific source on security group",
			source: `
resource "azurerm_network_security_group" "example" {
  name                = "tf-appsecuritygroup"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  
  security_rule {
	 source_port_range           = "any"
     destination_port_range      = ["22"]
     source_address_prefix       = "82.102.23.23"
     destination_address_prefix  = "*"
  }
}
`,
			mustExcludeResultCode: checks.AZUSSHAccessNotAllowedFromInternet,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
