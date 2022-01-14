package network

import (
	"github.com/aquasecurity/defsec/provider/azure/network"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) network.Network {
	return network.Network{
		SecurityGroups:         adaptSecurityGroups(modules),
		NetworkWatcherFlowLogs: adaptWatcherLogs(modules),
	}
}

func adaptSecurityGroups(modules []block.Module) []network.SecurityGroup {
	var securityGroups []network.SecurityGroup

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_network_security_group") {
			securityGroups = append(securityGroups, adaptSecurityGroup(resource, module))
		}
	}
	return securityGroups
}

func adaptWatcherLogs(modules []block.Module) []network.NetworkWatcherFlowLog {
	var watcherLogs []network.NetworkWatcherFlowLog

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_network_watcher_flow_log") {
			watcherLogs = append(watcherLogs, adaptWatcherLog(resource))
		}
	}
	return watcherLogs
}

func adaptSecurityGroup(resource block.Block, module block.Module) network.SecurityGroup {
	var inboundAllowRules []network.SecurityGroupRule
	var inboundDenyRules []network.SecurityGroupRule
	var outboundAllowRules []network.SecurityGroupRule
	var outboundDenyRules []network.SecurityGroupRule

	var securityRuleBlocks block.Blocks
	if resource.HasChild("security_rule") {
		securityRuleBlocks = append(securityRuleBlocks, resource.GetBlocks("security_rule")...)
	}

	securityRuleRes := module.GetReferencingResources(resource, "azurerm_network_security_rule", "network_security_group_name")
	securityRuleBlocks = append(securityRuleBlocks, securityRuleRes...)

	for _, ruleBlock := range securityRuleBlocks {
		var sourceAddresses []types.StringValue
		var sourcePortRanges []types.StringValue
		var destinationAddresses []types.StringValue
		var destinationPortRanges []types.StringValue

		accessAttr := ruleBlock.GetAttribute("access")
		directionAttr := ruleBlock.GetAttribute("direction")

		sourceAddressAttr := ruleBlock.GetAttribute("source_address_prefix")
		if sourceAddressAttr.IsNotEmpty() {
			sourceAddresses = append(sourceAddresses, sourceAddressAttr.AsStringValueOrDefault("", ruleBlock))
		}

		sourceAddressPrefixesAttr := ruleBlock.GetAttribute("source_address_prefixes")
		if sourceAddressPrefixesAttr.IsNotEmpty() {
			values := sourceAddressPrefixesAttr.ValueAsStrings()
			for _, value := range values {
				sourceAddresses = append(sourceAddresses, types.String(value, *ruleBlock.GetMetadata()))
			}
		}

		sourcePortRangeAttr := ruleBlock.GetAttribute("source_port_range")
		if sourcePortRangeAttr.IsNotEmpty() {
			if sourcePortRangeAttr.IsIterable() {
				values := sourcePortRangeAttr.ValueAsStrings()
				for _, value := range values {
					sourcePortRanges = append(sourcePortRanges, types.String(value, *ruleBlock.GetMetadata()))

				}
			} else {
				sourcePortRanges = append(sourcePortRanges, sourcePortRangeAttr.AsStringValueOrDefault("", ruleBlock))
			}
		}

		sourcePortRangesAttr := ruleBlock.GetAttribute("source_port_ranges")
		if sourcePortRangesAttr.IsNotEmpty() {
			values := sourcePortRangesAttr.ValueAsStrings()
			for _, value := range values {
				sourcePortRanges = append(sourcePortRanges, types.String(value, *ruleBlock.GetMetadata()))
			}
		}

		destinationAddressPrefixAttr := ruleBlock.GetAttribute("destination_address_prefix")
		if destinationAddressPrefixAttr.IsNotEmpty() {
			destinationAddresses = append(destinationAddresses, destinationAddressPrefixAttr.AsStringValueOrDefault("", ruleBlock))
		}

		destinationAddressPrefixesAttr := ruleBlock.GetAttribute("destination_address_prefixes")
		if destinationAddressPrefixesAttr.IsNotEmpty() {
			values := destinationAddressPrefixesAttr.ValueAsStrings()
			for _, value := range values {
				destinationAddresses = append(destinationAddresses, types.String(value, *ruleBlock.GetMetadata()))
			}
		}

		destinationPortRangeAttr := ruleBlock.GetAttribute("destination_port_range")
		if destinationPortRangeAttr.IsNotEmpty() {
			if destinationPortRangeAttr.IsIterable() {
				values := destinationPortRangeAttr.ValueAsStrings()
				for _, value := range values {
					destinationPortRanges = append(destinationPortRanges, types.String(value, *ruleBlock.GetMetadata()))
				}
			} else {
				destinationPortRanges = append(destinationPortRanges, destinationPortRangeAttr.AsStringValueOrDefault("", ruleBlock))
			}
		}

		destinationPortRangesAttr := ruleBlock.GetAttribute("destination_port_ranges")
		if destinationPortRangesAttr.IsNotEmpty() {
			values := destinationPortRangesAttr.ValueAsStrings()
			for _, value := range values {
				destinationPortRanges = append(destinationPortRanges, types.String(value, *ruleBlock.GetMetadata()))
			}
		}

		if accessAttr.Equals("Allow") && directionAttr.Equals("Inbound") {
			inboundAllowRules = append(inboundAllowRules, network.SecurityGroupRule{
				SourceAddresses:       sourceAddresses,
				SourcePortRanges:      sourcePortRanges,
				DestinationAddresses:  destinationAddresses,
				DestinationPortRanges: destinationPortRanges,
			})
		} else if accessAttr.Equals("Deny") && directionAttr.Equals("Inbound") {
			inboundDenyRules = append(inboundDenyRules, network.SecurityGroupRule{
				SourceAddresses:       sourceAddresses,
				SourcePortRanges:      sourcePortRanges,
				DestinationAddresses:  destinationAddresses,
				DestinationPortRanges: destinationPortRanges,
			})
		} else if accessAttr.Equals("Allow") && directionAttr.Equals("Outbound") {
			outboundAllowRules = append(outboundAllowRules, network.SecurityGroupRule{
				SourceAddresses:       sourceAddresses,
				SourcePortRanges:      sourcePortRanges,
				DestinationAddresses:  destinationAddresses,
				DestinationPortRanges: destinationPortRanges,
			})
		} else if accessAttr.Equals("Deny") && directionAttr.Equals("Outbound") {
			outboundDenyRules = append(outboundDenyRules, network.SecurityGroupRule{
				SourceAddresses:       sourceAddresses,
				SourcePortRanges:      sourcePortRanges,
				DestinationAddresses:  destinationAddresses,
				DestinationPortRanges: destinationPortRanges,
			})
		}
	}

	return network.SecurityGroup{
		InboundAllowRules:  inboundAllowRules,
		InboundDenyRules:   inboundDenyRules,
		OutboundAllowRules: outboundAllowRules,
		OutboundDenyRules:  outboundDenyRules,
	}
}

func adaptWatcherLog(resource block.Block) network.NetworkWatcherFlowLog {
	retentionPolicyBlock := resource.GetBlock("retention_policy")

	enabledAttr := retentionPolicyBlock.GetAttribute("enabled")
	enabledVal := enabledAttr.AsBoolValueOrDefault(false, retentionPolicyBlock)

	daysAttr := retentionPolicyBlock.GetAttribute("days")
	daysVal := daysAttr.AsIntValueOrDefault(0, retentionPolicyBlock)

	return network.NetworkWatcherFlowLog{
		RetentionPolicy: network.RetentionPolicy{
			Enabled: enabledVal,
			Days:    daysVal,
		},
	}
}
