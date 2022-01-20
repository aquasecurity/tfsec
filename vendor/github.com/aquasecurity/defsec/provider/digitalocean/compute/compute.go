package compute

import "github.com/aquasecurity/defsec/types"

type Compute struct {
	types.Metadata
	Firewalls          []Firewall
	LoadBalancers      []LoadBalancer
	Droplets           []Droplet
	KubernetesClusters []KubernetesCluster
}

type Firewall struct {
	types.Metadata
	OutboundRules []OutboundFirewallRule
	InboundRules  []InboundFirewallRule
}

type KubernetesCluster struct {
	types.Metadata
	SurgeUpgrade types.BoolValue
	AutoUpgrade  types.BoolValue
}

type LoadBalancer struct {
	types.Metadata
	ForwardingRules []ForwardingRule
}

type ForwardingRule struct {
	types.Metadata
	EntryProtocol types.StringValue
}

type OutboundFirewallRule struct {
	types.Metadata
	DestinationAddresses []types.StringValue
}

type InboundFirewallRule struct {
	types.Metadata
	SourceAddresses []types.StringValue
}

type Droplet struct {
	types.Metadata
	SSHKeys []types.StringValue
}

func (c *Compute) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Compute) GetRawValue() interface{} {
	return nil
}

func (f *Firewall) GetMetadata() *types.Metadata {
	return &f.Metadata
}

func (f *Firewall) GetRawValue() interface{} {
	return nil
}

func (k *KubernetesCluster) GetMetadata() *types.Metadata {
	return &k.Metadata
}

func (k *KubernetesCluster) GetRawValue() interface{} {
	return nil
}

func (l *LoadBalancer) GetMetadata() *types.Metadata {
	return &l.Metadata
}

func (l *LoadBalancer) GetRawValue() interface{} {
	return nil
}

func (f *ForwardingRule) GetMetadata() *types.Metadata {
	return &f.Metadata
}

func (f *ForwardingRule) GetRawValue() interface{} {
	return nil
}

func (o *OutboundFirewallRule) GetMetadata() *types.Metadata {
	return &o.Metadata
}

func (o *OutboundFirewallRule) GetRawValue() interface{} {
	return nil
}

func (i *InboundFirewallRule) GetMetadata() *types.Metadata {
	return &i.Metadata
}

func (i *InboundFirewallRule) GetRawValue() interface{} {
	return nil
}

func (d *Droplet) GetMetadata() *types.Metadata {
	return &d.Metadata
}

func (d *Droplet) GetRawValue() interface{} {
	return nil
}
