package compute

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/digitalocean/compute"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/cidr"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "DIG001",
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
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"digitalocean_firewall"},
		Base:           compute.CheckNoPublicIngress,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			inboundBlocks := resourceBlock.GetBlocks("inbound_rule")

			for _, inboundRuleBlock := range inboundBlocks {
				if inboundRuleBlock.MissingChild("source_addresses") {
					continue
				}
				sourceAddressesAttr := inboundRuleBlock.GetAttribute("source_addresses")
				if cidr.IsAttributeOpen(sourceAddressesAttr) {
					results.Add("Resource defines a fully open inbound_rule.", sourceAddressesAttr)
				}
			}
			return results
		},
	})
}
