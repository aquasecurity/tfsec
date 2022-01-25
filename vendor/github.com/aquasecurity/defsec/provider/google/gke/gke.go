package gke

import "github.com/aquasecurity/defsec/types"

type GKE struct {
	types.Metadata
	Clusters []Cluster
}

type Cluster struct {
	types.Metadata
	NodePools                []NodePool
	IPAllocationPolicy       IPAllocationPolicy
	MasterAuthorizedNetworks MasterAuthorizedNetworks
	NetworkPolicy            NetworkPolicy
	PrivateCluster           PrivateCluster
	LoggingService           types.StringValue
	MonitoringService        types.StringValue
	PodSecurityPolicy        PodSecurityPolicy
	ClusterMetadata          Metadata
	MasterAuth               MasterAuth
	NodeConfig               NodeConfig
	EnableShieldedNodes      types.BoolValue
	EnableLegacyABAC         types.BoolValue
	ResourceLabels           types.MapValue
	RemoveDefaultNodePool    types.BoolValue
}

type NodeConfig struct {
	types.Metadata
	ImageType              types.StringValue
	WorkloadMetadataConfig WorkloadMetadataConfig
	ServiceAccount         types.StringValue
}

type WorkloadMetadataConfig struct {
	types.Metadata
	NodeMetadata types.StringValue
}

type MasterAuth struct {
	types.Metadata
	ClientCertificate ClientCertificate
	Username          types.StringValue
	Password          types.StringValue
}

type ClientCertificate struct {
	types.Metadata
	IssueCertificate types.BoolValue
}

type Metadata struct {
	types.Metadata
	EnableLegacyEndpoints types.BoolValue
}

type PodSecurityPolicy struct {
	types.Metadata
	Enabled types.BoolValue
}

type PrivateCluster struct {
	types.Metadata
	EnablePrivateNodes types.BoolValue
}

type NetworkPolicy struct {
	types.Metadata
	Enabled types.BoolValue
}

type MasterAuthorizedNetworks struct {
	types.Metadata
	Enabled types.BoolValue
	CIDRs   []types.StringValue
}

type IPAllocationPolicy struct {
	types.Metadata
	Enabled types.BoolValue
}

type NodePool struct {
	types.Metadata
	Management Management
	NodeConfig NodeConfig
}

type Management struct {
	types.Metadata
	EnableAutoRepair  types.BoolValue
	EnableAutoUpgrade types.BoolValue
}

func (g *GKE) GetMetadata() *types.Metadata {
	return &g.Metadata
}

func (g *GKE) GetRawValue() interface{} {
	return nil
}

func (c *Cluster) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Cluster) GetRawValue() interface{} {
	return nil
}

func (n *NodeConfig) GetMetadata() *types.Metadata {
	return &n.Metadata
}

func (n *NodeConfig) GetRawValue() interface{} {
	return nil
}

func (w *WorkloadMetadataConfig) GetMetadata() *types.Metadata {
	return &w.Metadata
}

func (w *WorkloadMetadataConfig) GetRawValue() interface{} {
	return nil
}

func (m *MasterAuth) GetMetadata() *types.Metadata {
	return &m.Metadata
}

func (m *MasterAuth) GetRawValue() interface{} {
	return nil
}

func (c *ClientCertificate) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *ClientCertificate) GetRawValue() interface{} {
	return nil
}

func (m *Metadata) GetMetadata() *types.Metadata {
	return &m.Metadata
}

func (m *Metadata) GetRawValue() interface{} {
	return nil
}

func (p *PodSecurityPolicy) GetMetadata() *types.Metadata {
	return &p.Metadata
}

func (p *PodSecurityPolicy) GetRawValue() interface{} {
	return nil
}

func (p *PrivateCluster) GetMetadata() *types.Metadata {
	return &p.Metadata
}

func (p *PrivateCluster) GetRawValue() interface{} {
	return nil
}

func (n *NetworkPolicy) GetMetadata() *types.Metadata {
	return &n.Metadata
}

func (n *NetworkPolicy) GetRawValue() interface{} {
	return nil
}

func (m *MasterAuthorizedNetworks) GetMetadata() *types.Metadata {
	return &m.Metadata
}

func (m *MasterAuthorizedNetworks) GetRawValue() interface{} {
	return nil
}

func (i *IPAllocationPolicy) GetMetadata() *types.Metadata {
	return &i.Metadata
}

func (i *IPAllocationPolicy) GetRawValue() interface{} {
	return nil
}

func (n *NodePool) GetMetadata() *types.Metadata {
	return &n.Metadata
}

func (n *NodePool) GetRawValue() interface{} {
	return nil
}

func (m *Management) GetMetadata() *types.Metadata {
	return &m.Metadata
}

func (m *Management) GetRawValue() interface{} {
	return nil
}
