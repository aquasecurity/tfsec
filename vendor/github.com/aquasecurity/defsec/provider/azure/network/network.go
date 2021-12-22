package network

import "github.com/aquasecurity/defsec/types"

type Network struct {
	SecurityGroups         []SecurityGroup
	NetworkWatcherFlowLogs []NetworkWatcherFlowLog
}

type SecurityGroup struct {
	InboundAllowRules  []SecurityGroupRule
	InboundDenyRules   []SecurityGroupRule
	OutboundAllowRules []SecurityGroupRule
	OutboundDenyRules  []SecurityGroupRule
}

type SecurityGroupRule struct {
	SourceAddresses       []types.StringValue
	SourcePortRanges      []types.StringValue
	DestinationAddresses  []types.StringValue
	DestinationPortRanges []types.StringValue
}

type NetworkWatcherFlowLog struct {
	RetentionPolicy RetentionPolicy
}

type RetentionPolicy struct {
	Enabled types.BoolValue
	Days    types.IntValue
}
