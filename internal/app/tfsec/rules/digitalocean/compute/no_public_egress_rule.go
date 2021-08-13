package compute

// generator-locked
import (
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/cidr"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "DIG002",
		Service:   "compute",
		ShortCode: "no-public-egress",
		Documentation: rule.RuleDocumentation{
			Summary: "The firewall has an outbound rule with open access",
			Explanation: `
Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.
`,
			Impact:     "The port is exposed for ingress from the internet",
			Resolution: "Set a more restrictive cidr range",
			BadExample: []string{`
resource "digitalocean_firewall" "bad_example" {
	name = "only-22-80-and-443"
  
	droplet_ids = [digitalocean_droplet.web.id]
  
	outbound_rule {
	  protocol         = "tcp"
	  port_range       = "22"
	  destination_addresses = ["0.0.0.0/0", "::/0"]
	}
}
`},
			GoodExample: []string{`
resource "digitalocean_firewall" "good_example" {
	name = "only-22-80-and-443"
  
	droplet_ids = [digitalocean_droplet.web.id]
  
	outbound_rule {
	  protocol         = "tcp"
	  port_range       = "22"
	  destination_addresses = ["192.168.1.0/24", "2002:1:2::/48"]
	}
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/firewall",
				"https://docs.digitalocean.com/products/networking/firewalls/how-to/configure-rules/",
			},
		},
		Provider:        provider.DigitalOceanProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"digitalocean_firewall"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {
			inboundBlocks := resourceBlock.GetBlocks("outbound_rule")

			for _, inboundRuleBlock := range inboundBlocks {
				if inboundRuleBlock.MissingChild("destination_addresses") {
					continue
				}
				destinationAddressesAttr := inboundRuleBlock.GetAttribute("destination_addresses")
				if cidr.IsAttributeOpen(destinationAddressesAttr) {
					set.AddResult().
						WithDescription("Resource '%s' defines a fully open outbound_rule.", resourceBlock.FullName()).
						WithAttribute(destinationAddressesAttr)
				}
			}
		},
	})
}
