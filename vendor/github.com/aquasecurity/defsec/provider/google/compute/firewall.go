package compute

import "github.com/aquasecurity/defsec/types"

type Firewall struct {
	types.Metadata
	Name         types.StringValue
	IngressRules []IngressRule
	EgressRules  []EgressRule
}

type FirewallRule struct {
	types.Metadata
	Enforced types.BoolValue
	IsAllow  types.BoolValue
	Protocol types.StringValue
	Ports    []types.IntValue
}

type IngressRule struct {
	types.Metadata
	FirewallRule
	SourceRanges []types.StringValue
}

type EgressRule struct {
	types.Metadata
	FirewallRule
	DestinationRanges []types.StringValue
}

func (f *Firewall) GetMetadata() *types.Metadata {
	return &f.Metadata
}

func (f *Firewall) GetRawValue() interface{} {
	return nil
}

func (f *FirewallRule) GetMetadata() *types.Metadata {
	return &f.Metadata
}

func (f *FirewallRule) GetRawValue() interface{} {
	return nil
}

func (i *IngressRule) GetMetadata() *types.Metadata {
	return &i.Metadata
}

func (i *IngressRule) GetRawValue() interface{} {
	return nil
}

func (e *EgressRule) GetMetadata() *types.Metadata {
	return &e.Metadata
}

func (e *EgressRule) GetRawValue() interface{} {
	return nil
}
