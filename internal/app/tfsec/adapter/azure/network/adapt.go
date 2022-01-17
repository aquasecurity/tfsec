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
		accessAttr := ruleBlock.GetAttribute("access")
		directionAttr := ruleBlock.GetAttribute("direction")

		if accessAttr.Equals("Allow") && directionAttr.Equals("Inbound") {
			inboundAllowRules = append(inboundAllowRules, adaptSGRule(ruleBlock))
		}
		if accessAttr.Equals("Deny") && directionAttr.Equals("Inbound") {
			inboundDenyRules = append(inboundDenyRules, adaptSGRule(ruleBlock))

		}
		if accessAttr.Equals("Allow") && directionAttr.Equals("Outbound") {
			outboundAllowRules = append(outboundAllowRules, adaptSGRule(ruleBlock))
		}
		if accessAttr.Equals("Deny") && directionAttr.Equals("Outbound") {
			outboundDenyRules = append(outboundDenyRules, adaptSGRule(ruleBlock))
		}
	}

	return network.SecurityGroup{
		InboundAllowRules:  inboundAllowRules,
		InboundDenyRules:   inboundDenyRules,
		OutboundAllowRules: outboundAllowRules,
		OutboundDenyRules:  outboundDenyRules,
	}
}

func adaptSGRule(resource block.Block) network.SecurityGroupRule {
	var sourceAddresses []types.StringValue
	var sourcePortRanges []types.StringValue
	var destinationAddresses []types.StringValue
	var destinationPortRanges []types.StringValue

	sourceAddressAttr := resource.GetAttribute("source_address_prefix")
	sourceAddresses = append(sourceAddresses, sourceAddressAttr.AsStringValueOrDefault("", resource))

	sourceAddressPrefixesAttr := resource.GetAttribute("source_address_prefixes")
	values := sourceAddressPrefixesAttr.ValueAsStrings()
	for _, value := range values {
		sourceAddresses = append(sourceAddresses, types.String(value, *resource.GetMetadata()))
	}

	sourcePortRangeAttr := resource.GetAttribute("source_port_range")
	if sourcePortRangeAttr.IsIterable() {
		values := sourcePortRangeAttr.ValueAsStrings()
		for _, value := range values {
			sourcePortRanges = append(sourcePortRanges, types.String(value, *resource.GetMetadata()))

		}
	} else {
		sourcePortRanges = append(sourcePortRanges, sourcePortRangeAttr.AsStringValueOrDefault("", resource))
	}

	sourcePortRangesAttr := resource.GetAttribute("source_port_ranges")
	sourcePortList := sourcePortRangesAttr.ValueAsStrings()
	for _, sourcePort := range sourcePortList {
		sourcePortRanges = append(sourcePortRanges, types.String(sourcePort, *resource.GetMetadata()))
	}

	destinationAddressPrefixAttr := resource.GetAttribute("destination_address_prefix")
	destinationAddresses = append(destinationAddresses, destinationAddressPrefixAttr.AsStringValueOrDefault("", resource))

	destinationAddressPrefixesAttr := resource.GetAttribute("destination_address_prefixes")
	destinationAddList := destinationAddressPrefixesAttr.ValueAsStrings()
	for _, destination := range destinationAddList {
		destinationAddresses = append(destinationAddresses, types.String(destination, *resource.GetMetadata()))
	}

	destinationPortRangeAttr := resource.GetAttribute("destination_port_range")
	if destinationPortRangeAttr.IsIterable() {
		values := destinationPortRangeAttr.ValueAsStrings()
		for _, value := range values {
			destinationPortRanges = append(destinationPortRanges, types.String(value, *resource.GetMetadata()))
		}
	} else {
		destinationPortRanges = append(destinationPortRanges, destinationPortRangeAttr.AsStringValueOrDefault("", resource))
	}

	destinationPortRangesAttr := resource.GetAttribute("destination_port_ranges")
	destinationPortsList := destinationPortRangesAttr.ValueAsStrings()
	for _, destination := range destinationPortsList {
		destinationPortRanges = append(destinationPortRanges, types.String(destination, *resource.GetMetadata()))
	}

	return network.SecurityGroupRule{
		SourceAddresses:       sourceAddresses,
		SourcePortRanges:      sourcePortRanges,
		DestinationAddresses:  destinationAddresses,
		DestinationPortRanges: destinationPortRanges,
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
