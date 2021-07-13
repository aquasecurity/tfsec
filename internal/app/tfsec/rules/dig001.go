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

const DIGFirewallHasOpenInboundAccess = "DIG001"
const DIGFirewallHasOpenInboundAccessDescription = "The firewall has an inbound rule with open access"
const DIGFirewallHasOpenInboundAccessImpact = "Your port is exposed to the internet"
const DIGFirewallHasOpenInboundAccessResolution = "Set a more restrictive CIRDR range"
const DIGFirewallHasOpenInboundAccessExplanation = `
Opening up ports to connect out to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that are explicitly required where possible.
`
const DIGFirewallHasOpenInboundAccessBadExample = `
resource "digitalocean_firewall" "bad_example" {
	name = "only-22-80-and-443"
  
	droplet_ids = [digitalocean_droplet.web.id]
  
	inbound_rule {
	  protocol         = "tcp"
	  port_range       = "22"
	  source_addresses = ["0.0.0.0/0", "::/0"]
	}
}
`
const DIGFirewallHasOpenInboundAccessGoodExample = `
resource "digitalocean_firewall" "good_example" {
	name = "only-22-80-and-443"
  
	droplet_ids = [digitalocean_droplet.web.id]
  
	inbound_rule {
	  protocol         = "tcp"
	  port_range       = "22"
	  source_addresses = ["192.168.1.0/24", "2002:1:2::/48"]
	}
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: DIGFirewallHasOpenInboundAccess,
		Documentation: rule.RuleDocumentation{
			Summary:     DIGFirewallHasOpenInboundAccessDescription,
			Explanation: DIGFirewallHasOpenInboundAccessExplanation,
			Impact:      DIGFirewallHasOpenInboundAccessImpact,
			Resolution:  DIGFirewallHasOpenInboundAccessResolution,
			BadExample:  DIGFirewallHasOpenInboundAccessBadExample,
			GoodExample: DIGFirewallHasOpenInboundAccessGoodExample,
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

			inboundBlocks := resourceBlock.GetBlocks("inbound_rule")

			for _, inboundRuleBlock := range inboundBlocks {
				if inboundRuleBlock.MissingChild("source_addresses") {
					continue
				}
				sourceAddressesAttr := inboundRuleBlock.GetAttribute("source_addresses")
				if isOpenCidr(sourceAddressesAttr) {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' defines a fully open inbound_rule.", resourceBlock.FullName())).
							WithRange(sourceAddressesAttr.Range()).
							WithAttributeAnnotation(sourceAddressesAttr),
					)
				}
			}
		},
	})
}
