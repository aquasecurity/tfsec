package gke

import "github.com/aquasecurity/defsec/types"

type GKE struct {
	Clusters []Cluster
}

type Cluster struct {
	NodePools                []NodePool
	IPAllocationPolicy       IPAllocationPolicy
	MasterAuthorizedNetworks MasterAuthorizedNetworks
	NetworkPolicy            NetworkPolicy
	PrivateCluster           PrivateCluster
	LoggingService           types.StringValue
	MonitoringService        types.StringValue
	PodSecurityPolicy        PodSecurityPolicy
	Metadata                 Metadata
	MasterAuth               MasterAuth
	NodeConfig               NodeConfig
	EnableShieldedNodes      types.BoolValue
	EnableLegacyABAC         types.BoolValue
	ResourceLabels           types.MapValue
	RemoveDefaultNodePool    types.BoolValue
}

type NodeConfig struct {
	ImageType              types.StringValue
	WorkloadMetadataConfig WorkloadMetadataConfig
	ServiceAccount         types.StringValue
}

type WorkloadMetadataConfig struct {
	NodeMetadata types.StringValue
}

type MasterAuth struct {
	ClientCertificate ClientCertificate
	Username          types.StringValue
	Password          types.StringValue
}

type ClientCertificate struct {
	IssueCertificate types.BoolValue
}

type Metadata struct {
	EnableLegacyEndpoints types.BoolValue
}

type PodSecurityPolicy struct {
	Enabled types.BoolValue
}

type PrivateCluster struct {
	EnablePrivateNodes types.BoolValue
}

type NetworkPolicy struct {
	Enabled types.BoolValue
}

type MasterAuthorizedNetworks struct {
	Enabled types.BoolValue
	CIDRs   []types.StringValue
}

type IPAllocationPolicy struct {
	Enabled types.BoolValue
}

type NodePool struct {
	Management Management
	NodeConfig NodeConfig
}

type Management struct {
	EnableAutoRepair  types.BoolValue
	EnableAutoUpgrade types.BoolValue
}
