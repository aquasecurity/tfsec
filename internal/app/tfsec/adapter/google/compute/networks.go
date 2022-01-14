package compute

import (
	"strconv"
	"strings"

	"github.com/aquasecurity/defsec/provider/google/compute"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func adaptNetworks(modules block.Modules) (networks []compute.Network) {

	for _, module := range modules {

		networkMap := make(map[string]compute.Network)

		for _, networkBlock := range module.GetResourcesByType("google_compute_network") {
			var network compute.Network
			network.Metadata = networkBlock.Metadata()
			networkMap[networkBlock.ID()] = network
		}

		for _, subnetworkBlock := range module.GetResourcesByType("google_compute_subnetwork") {

			var subnetwork compute.SubNetwork
			subnetwork.Metadata = subnetworkBlock.Metadata()

			// logging
			if logConfigBlock := subnetworkBlock.GetBlock("log_config"); logConfigBlock.IsNotNil() {
				subnetwork.EnableFlowLogs = types.BoolExplicit(true, subnetworkBlock.GetBlock("log_config").Metadata())
			} else {
				subnetwork.EnableFlowLogs = types.BoolDefault(false, subnetworkBlock.Metadata())
			}

			nwAttr := subnetworkBlock.GetAttribute("network")
			if nwAttr.IsNotNil() {
				if nwblock, err := module.GetReferencedBlock(nwAttr, subnetworkBlock); err == nil {
					if network, ok := networkMap[nwblock.ID()]; ok {
						network.Subnetworks = append(network.Subnetworks, subnetwork)
						networkMap[nwblock.ID()] = network
						continue
					}
				}
			}

			var placeholder compute.Network
			placeholder.Metadata = types.NewUnmanagedMetadata(subnetworkBlock.Range(), subnetwork.Reference())
			placeholder.Subnetworks = append(placeholder.Subnetworks, subnetwork)
			networks = append(networks, placeholder)
		}

		for _, firewallBlock := range module.GetResourcesByType("google_compute_firewall") {

			var firewall compute.Firewall
			firewall.Metadata = firewallBlock.Metadata()
			firewall.Name = firewallBlock.GetAttribute("name").AsStringValueOrDefault("", firewallBlock)

			for _, allowBlock := range firewallBlock.GetBlocks("allow") {
				adaptFirewallRule(&firewall, firewallBlock, allowBlock, true)
			}
			for _, denyBlock := range firewallBlock.GetBlocks("deny") {
				adaptFirewallRule(&firewall, firewallBlock, denyBlock, false)
			}

			nwAttr := firewallBlock.GetAttribute("network")
			if nwAttr.IsNotNil() {
				if nwblock, err := module.GetReferencedBlock(nwAttr, firewallBlock); err == nil {
					if network, ok := networkMap[nwblock.ID()]; ok {
						network.Firewall = &firewall
						networkMap[nwblock.ID()] = network
						continue
					}
				}
			}

			var placeholder compute.Network
			placeholder.Metadata = types.NewUnmanagedMetadata(firewallBlock.Range(), firewall.Reference())
			placeholder.Firewall = &firewall
			networks = append(networks, placeholder)
		}

		for _, nw := range networkMap {
			networks = append(networks, nw)
		}
	}

	return networks
}

func expandRange(ports string, attr block.Attribute) []types.IntValue {
	ports = strings.ReplaceAll(ports, " ", "")
	if !strings.Contains(ports, "-") {
		i, err := strconv.Atoi(ports)
		if err != nil {
			return nil
		}
		return []types.IntValue{
			types.Int(i, attr.Metadata()),
		}
	}
	parts := strings.Split(ports, "-")
	if len(parts) != 2 {
		return nil
	}
	start, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil
	}
	end, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil
	}
	var output []types.IntValue
	for i := start; i <= end; i++ {
		output = append(output, types.Int(i, attr.Metadata()))
	}
	return output
}

func adaptFirewallRule(firewall *compute.Firewall, firewallBlock, ruleBlock block.Block, allow bool) {
	protocolAttr := ruleBlock.GetAttribute("protocol")
	portsAttr := ruleBlock.GetAttribute("ports")

	var ports []types.IntValue
	for _, portStr := range portsAttr.ValueAsStrings() {
		ports = append(ports, expandRange(portStr, portsAttr)...)
	}

	// ingress by default
	isEgress := firewallBlock.GetAttribute("direction").Equals("EGRESS", block.IgnoreCase)

	rule := compute.FirewallRule{
		Metadata: firewallBlock.Metadata(),
		IsAllow:  types.Bool(allow, ruleBlock.Metadata()),
		Ports:    ports,
		Protocol: protocolAttr.AsStringValueOrDefault("tcp", ruleBlock),
	}

	disabledAttr := firewallBlock.GetAttribute("disabled")
	if disabledAttr.IsNil() {
		rule.Enforced = types.BoolDefault(true, firewallBlock.Metadata())
	} else if disabledAttr.IsTrue() {
		rule.Enforced = types.Bool(false, disabledAttr.Metadata())
	} else {
		rule.Enforced = types.Bool(true, disabledAttr.Metadata())
	}

	if isEgress {
		var destinations []types.StringValue
		if destinationAttr := firewallBlock.GetAttribute("destination_ranges"); destinationAttr.IsNotNil() {
			for _, destination := range destinationAttr.ValueAsStrings() {
				destinations = append(destinations, types.String(destination, destinationAttr.Metadata()))
			}
		}
		firewall.EgressRules = append(firewall.EgressRules, compute.EgressRule{
			Metadata:          firewallBlock.Metadata(),
			FirewallRule:      rule,
			DestinationRanges: destinations,
		})
	} else {
		var sources []types.StringValue
		if sourceAttr := firewallBlock.GetAttribute("source_ranges"); sourceAttr.IsNotNil() {
			for _, source := range sourceAttr.ValueAsStrings() {
				sources = append(sources, types.String(source, sourceAttr.Metadata()))
			}
		}
		firewall.IngressRules = append(firewall.IngressRules, compute.IngressRule{
			Metadata:     firewallBlock.Metadata(),
			FirewallRule: rule,
			SourceRanges: sources,
		})
	}

}
