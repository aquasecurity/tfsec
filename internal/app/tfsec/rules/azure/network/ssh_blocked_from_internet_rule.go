package network

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
		LegacyID:  "AZU017",
		Service:   "network",
		ShortCode: "ssh-blocked-from-internet",
		Documentation: rule.RuleDocumentation{
			Summary:    "SSH access should not be accessible from the Internet, should be blocked on port 22",
			Impact:     "Its dangerous to allow SSH access from the internet",
			Resolution: "Block port 22 access from the internet",
			Explanation: `
SSH access can be configured on either the network security group or in the network security group rule. 

SSH access should not be permitted from the internet (*, 0.0.0.0, /0, internet, any)

`,
			BadExample: []string{`
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
`},
			GoodExample: []string{`
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
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/network_security_group#security_rule",
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_rule#source_port_ranges",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_network_security_group", "azurerm_network_security_rule"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			var securityRules block.Blocks
			if resourceBlock.IsResourceType("azurerm_network_security_group") {
				securityRules = resourceBlock.GetBlocks("security_rule")
			} else {
				securityRules = append(securityRules, resourceBlock)
			}

			for _, securityRule := range securityRules {
				if securityRule.HasChild("access") && securityRule.GetAttribute("access").Equals("Deny", block.IgnoreCase) {
					continue
				}
				if securityRule.HasChild("destination_port_range") && securityRule.GetAttribute("destination_port_range").Contains("22") {
					if securityRule.HasChild("source_address_prefix") {
						if securityRule.GetAttribute("source_address_prefix").IsAny("*", "0.0.0.0", "/0", "internet", "any") {
							set.AddResult().
								WithDescription("Resource '%s' has a .", resourceBlock.FullName()).WithBlock(securityRule)
						}
					}
				}
			}
		},
	})
}
