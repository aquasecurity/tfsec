package compute

import "github.com/aquasecurity/defsec/types"

type Compute struct {
	Firewalls          []Firewall
	LoadBalancers      []LoadBalancer
	Droplets           []Droplet
	KubernetesClusters []KubernetesCluster
}

type Firewall struct {
	OutboundRules []OutboundFirewallRule
	InboundRules  []InboundFirewallRule
}

type KubernetesCluster struct {
	types.Metadata
	SurgeUpgrade types.BoolValue
	AutoUpgrade  types.BoolValue
}

type LoadBalancer struct {
	ForwardingRules []ForwardingRule
}

type ForwardingRule struct {
	EntryProtocol types.StringValue
}

type OutboundFirewallRule struct {
	DestinationAddresses []types.StringValue
}

type InboundFirewallRule struct {
	SourceAddresses []types.StringValue
}

type Droplet struct {
	types.Metadata
	SSHKeys []types.StringValue
}

func (kc KubernetesCluster) GetMetadata() *types.Metadata {
	return &kc.Metadata
}

func (d Droplet) GetMetadata() *types.Metadata {
	return &d.Metadata
}

func (d Droplet) GetRawValue() interface{} {
	return nil
}
