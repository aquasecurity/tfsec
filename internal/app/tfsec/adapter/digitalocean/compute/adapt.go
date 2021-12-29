package compute

import (
	"github.com/aquasecurity/defsec/provider/digitalocean/compute"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) compute.Compute {
	return compute.Compute{
		Droplets:  adaptDroplets(modules),
		Firewalls: adaptFirewalls(modules),
	}
}

func adaptDroplets(module block.Modules) []compute.Droplet {
	var droplets []compute.Droplet

	for _, module := range module {
		for _, block := range module.GetResourcesByType("digitalocean_droplet") {
			droplet := compute.Droplet{
				Metadata: *(block.GetMetadata()),
			}
			sshKeys := block.GetAttribute("ssh_keys")
			if sshKeys != nil {
				droplet.SSHKeys = []types.StringValue{}
				for _, value := range sshKeys.ValueAsStrings() {
					droplet.SSHKeys = append(droplet.SSHKeys, types.String(value, sshKeys.Metadata()))
				}
			}

			droplets = append(droplets, droplet)
		}
	}
	return droplets
}

func adaptFirewalls(module block.Modules) []compute.Firewall {
	var firewalls []compute.Firewall

	for _, module := range module {
		for _, block := range module.GetResourcesByType("digitalocean_firewall") {
			firewall := compute.Firewall{}
			inboundRules := block.GetBlock("inbound_rule")
			// outboundRules := block.GetBlock("outbound_rule")

			// for _, from := range ingressBlock.GetBlocks("from") {
			// 	cidrAtrr := from.GetBlock("ip_block").GetAttribute("cidr")
			// 	cidrVal := cidrAtrr.AsStringValueOrDefault("", from)

			// 	spec.Ingress.SourceCIDRs = append(spec.Ingress.SourceCIDRs, cidrVal)
			// }

			/*
				inbound_rule {
					protocol         = "tcp"
					port_range       = "22"
					source_addresses = ["0.0.0.0/0", "::/0"]
				}
			*/

			compute.InboundFirewallRule.SourceAddresses = inboundRules.GetAttribute("source_addresses").ValueAsStrings()
			firewalls = append(firewalls, firewall)

		}
	}

	return firewalls
}

func adaptLoadBalancers(module block.Modules) []compute.LoadBalancer {
	return nil
}
