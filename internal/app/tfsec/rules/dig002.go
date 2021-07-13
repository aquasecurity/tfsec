package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
)

const DIGFirewallHasOpenOutboundAccess = "DIG002"
const DIGFirewallHasOpenOutboundAccessDescription = "The firewall has an outbound rule with open access"
const DIGFirewallHasOpenOutboundAccessImpact = "The port is exposed for ingress from the internet"
const DIGFirewallHasOpenOutboundAccessResolution = "Set a more restrictive cidr range"
const DIGFirewallHasOpenOutboundAccessExplanation = `
Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.
`
const DIGFirewallHasOpenOutboundAccessBadExample = `
resource "digitalocean_firewall" "bad_example" {
	name = "only-22-80-and-443"
  
	droplet_ids = [digitalocean_droplet.web.id]
  
	outbound_rule {
	  protocol         = "tcp"
	  port_range       = "22"
	  destination_addresses = ["0.0.0.0/0", "::/0"]
	}
}
`
const DIGFirewallHasOpenOutboundAccessGoodExample = `
resource "digitalocean_firewall" "good_example" {
	name = "only-22-80-and-443"
  
	droplet_ids = [digitalocean_droplet.web.id]
  
	outbound_rule {
	  protocol         = "tcp"
	  port_range       = "22"
	  destination_addresses = ["192.168.1.0/24", "2002:1:2::/48"]
	}
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: DIGFirewallHasOpenOutboundAccess,
		Documentation: rule.RuleDocumentation{
			Summary:     DIGFirewallHasOpenOutboundAccessDescription,
			Explanation: DIGFirewallHasOpenOutboundAccessExplanation,
			Impact:      DIGFirewallHasOpenOutboundAccessImpact,
			Resolution:  DIGFirewallHasOpenOutboundAccessResolution,
			BadExample:  DIGFirewallHasOpenOutboundAccessBadExample,
			GoodExample: DIGFirewallHasOpenOutboundAccessGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/firewall",
				"https://docs.digitalocean.com/products/networking/firewalls/how-to/configure-rules/",
			},
		},
		Provider:        provider.DigitalOceanProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"digitalocean_firewall"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {
			inboundBlocks := resourceBlock.GetBlocks("outbound_rule")

			for _, inboundRuleBlock := range inboundBlocks {
				if inboundRuleBlock.MissingChild("destination_addresses") {
					continue
				}
				destinationAddressesAttr := inboundRuleBlock.GetAttribute("destination_addresses")
				if isOpenCidr(destinationAddressesAttr) {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' defines a fully open outbound_rule.", resourceBlock.FullName())).
							WithRange(destinationAddressesAttr.Range()).
							WithAttributeAnnotation(destinationAddressesAttr),
					)
				}
			}
		},
	})
}
