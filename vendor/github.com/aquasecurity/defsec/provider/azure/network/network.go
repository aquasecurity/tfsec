package network

import "github.com/aquasecurity/defsec/types"

type Network struct {
	types.Metadata
	SecurityGroups         []SecurityGroup
	NetworkWatcherFlowLogs []NetworkWatcherFlowLog
}

type SecurityGroup struct {
	types.Metadata
	Rules []SecurityGroupRule
}

type SecurityGroupRule struct {
	types.Metadata
	Outbound              types.BoolValue
	Allow                 types.BoolValue
	SourceAddresses       []types.StringValue
	SourcePortRanges      []types.StringValue
	DestinationAddresses  []types.StringValue
	DestinationPortRanges []types.StringValue
}

type NetworkWatcherFlowLog struct {
	types.Metadata
	RetentionPolicy RetentionPolicy
}

type RetentionPolicy struct {
	types.Metadata
	Enabled types.BoolValue
	Days    types.IntValue
}

func (n *Network) GetMetadata() *types.Metadata {
	return &n.Metadata
}

func (n *Network) GetRawValue() interface{} {
	return nil
}

func (s *SecurityGroup) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s *SecurityGroup) GetRawValue() interface{} {
	return nil
}

func (s *SecurityGroupRule) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s *SecurityGroupRule) GetRawValue() interface{} {
	return nil
}

func (n *NetworkWatcherFlowLog) GetMetadata() *types.Metadata {
	return &n.Metadata
}

func (n *NetworkWatcherFlowLog) GetRawValue() interface{} {
	return nil
}

func (r *RetentionPolicy) GetMetadata() *types.Metadata {
	return &r.Metadata
}

func (r *RetentionPolicy) GetRawValue() interface{} {
	return nil
}
