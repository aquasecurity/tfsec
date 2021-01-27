package checks

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AZUSSHAccessNotAllowedFromInternet scanner.RuleCode = "AZU017"
const AZUSSHAccessNotAllowedFromInternetDescription scanner.RuleSummary = "SSH access should not be accessible from the Internet, should be blocked on port 22"
const AZUSSHAccessNotAllowedFromInternetExplanation = `
SSH access can be configured on either the network security group or in the network security group rule. 

SSH access should not be permitted from the internet (*, 0.0.0.0, /0, internet, any)

`
const AZUSSHAccessNotAllowedFromInternetBadExample = `
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

resource "azurerm_network_security_group" "example" {
  name                = "tf-appsecuritygroup"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  
  security_rule {
	 source_port_range           = "any"
     destination_port_range      = ["22"]
     source_address_prefix       = "*"
     destination_address_prefix  = "*"
  }
}
`
const AZUSSHAccessNotAllowedFromInternetGoodExample = `
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
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AZUSSHAccessNotAllowedFromInternet,
		Documentation: scanner.CheckDocumentation{
			Summary:     AZUSSHAccessNotAllowedFromInternetDescription,
			Explanation: AZUSSHAccessNotAllowedFromInternetExplanation,
			BadExample:  AZUSSHAccessNotAllowedFromInternetBadExample,
			GoodExample: AZUSSHAccessNotAllowedFromInternetGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/network_security_group#security_rule",
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_rule#source_port_ranges",
			},
		},
		Provider:       scanner.AzureProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_network_security_group", "azurerm_network_security_rule"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			var securityRules parser.Blocks
			if block.IsResourceType("azurerm_network_security_group") {
				securityRules = block.GetBlocks("security_rule")
			} else {
				securityRules = append(securityRules, block)
			}

			for _, rule := range securityRules {
				if rule.HasChild("destination_port_range") && rule.GetAttribute("destination_port_range").Contains("22") {
					if rule.HasChild("source_address_prefix") {
						if rule.GetAttribute("source_address_prefix").IsAny("*", "0.0.0.0", "/0", "internet", "any") {
							return []scanner.Result{
								check.NewResult(
									fmt.Sprintf("Resource '%s' has a .", block.FullName()),
									block.Range(),
									scanner.SeverityError,
								),
							}
						}
					}
				}
			}
			return nil
		},
	})
}
