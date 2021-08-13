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
		LegacyID:  "DIG001",
		Service:   "compute",
		ShortCode: "no-public-ingress",
		Documentation: rule.RuleDocumentation{
			Summary: "The firewall has an inbound rule with open access",
			Explanation: `
Opening up ports to connect out to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that are explicitly required where possible.
`,
			Impact:     "Your port is exposed to the internet",
			Resolution: "Set a more restrictive CIRDR range",
			BadExample: []string{`
resource "digitalocean_firewall" "bad_example" {
	name = "only-22-80-and-443"
  
	droplet_ids = [digitalocean_droplet.web.id]
  
	inbound_rule {
	  protocol         = "tcp"
	  port_range       = "22"
	  source_addresses = ["0.0.0.0/0", "::/0"]
	}
}
`},
			GoodExample: []string{`
resource "digitalocean_firewall" "good_example" {
	name = "only-22-80-and-443"
  
	droplet_ids = [digitalocean_droplet.web.id]
  
	inbound_rule {
	  protocol         = "tcp"
	  port_range       = "22"
	  source_addresses = ["192.168.1.0/24", "2002:1:2::/48"]
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

			inboundBlocks := resourceBlock.GetBlocks("inbound_rule")

			for _, inboundRuleBlock := range inboundBlocks {
				if inboundRuleBlock.MissingChild("source_addresses") {
					continue
				}
				sourceAddressesAttr := inboundRuleBlock.GetAttribute("source_addresses")
				if cidr.IsAttributeOpen(sourceAddressesAttr) {
					set.AddResult().
						WithDescription("Resource '%s' defines a fully open inbound_rule.", resourceBlock.FullName()).
						WithAttribute(sourceAddressesAttr)
				}
			}
		},
	})
}
