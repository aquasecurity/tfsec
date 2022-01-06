package compute

import (
	"fmt"

	"github.com/aquasecurity/defsec/provider/digitalocean/compute"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) compute.Compute {
	return compute.Compute{
		Droplets:  adaptDroplets(modules),
		Firewalls: adaptFirewalls(modules),
		// LoadBalancers: adaptLoadBalancers(modules),
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
			inboundRules := block.GetBlocks("inbound_rule")
			outboundRules := block.GetBlocks("outbound_rule")

			inboundFirewallRules := []compute.InboundFirewallRule{}
			for _, inBoundRule := range inboundRules {
				inboundFirewallRule := compute.InboundFirewallRule{}
				ibSourceAddresses := inBoundRule.GetAttribute("source_addresses")
				fmt.Println(ibSourceAddresses)
				if ibSourceAddresses != nil {
					inboundFirewallRule.SourceAddresses = []types.StringValue{}
					for _, value := range ibSourceAddresses.ValueAsStrings() {
						inboundFirewallRule.SourceAddresses = append(inboundFirewallRule.SourceAddresses, types.String(value, ibSourceAddresses.Metadata()))
					}
				}
				inboundFirewallRules = append(inboundFirewallRules, inboundFirewallRule)
			}
			fmt.Println(inboundFirewallRules)
			firewall.InboundRules = inboundFirewallRules

			outboundFirewallRules := []compute.OutboundFirewallRule{}
			for _, outBoundRule := range outboundRules {
				outboundFirewallRule := compute.OutboundFirewallRule{}
				obDestinationAddresses := outBoundRule.GetAttribute("destination_addresses")
				if obDestinationAddresses != nil {
					outboundFirewallRule.DestinationAddresses = []types.StringValue{}
					for _, value := range obDestinationAddresses.ValueAsStrings() {
						outboundFirewallRule.DestinationAddresses = append(outboundFirewallRule.DestinationAddresses, types.String(value, obDestinationAddresses.Metadata()))
					}
				}
				outboundFirewallRules = append(outboundFirewallRules, outboundFirewallRule)

			}
			firewall.OutboundRules = outboundFirewallRules
			firewalls = append(firewalls, firewall)
		}
	}

	return firewalls
}

func adaptLoadBalancers(module block.Modules) []compute.LoadBalancer {
	return nil
}
