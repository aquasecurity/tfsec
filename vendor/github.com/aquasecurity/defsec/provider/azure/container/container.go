package container

import "github.com/aquasecurity/defsec/types"

type Container struct {
	types.Metadata
	KubernetesClusters []KubernetesCluster
}

type KubernetesCluster struct {
	types.Metadata
	NetworkProfile              NetworkProfile
	EnablePrivateCluster        types.BoolValue
	APIServerAuthorizedIPRanges []types.StringValue
	AddonProfile                AddonProfile
	RoleBasedAccessControl      RoleBasedAccessControl
}

type RoleBasedAccessControl struct {
	types.Metadata
	Enabled types.BoolValue
}

type AddonProfile struct {
	types.Metadata
	OMSAgent OMSAgent
}

type OMSAgent struct {
	types.Metadata
	Enabled types.BoolValue
}

type NetworkProfile struct {
	types.Metadata
	NetworkPolicy types.StringValue // "", "calico", "azure"
}

func (c *Container) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Container) GetRawValue() interface{} {
	return nil
}

func (k *KubernetesCluster) GetMetadata() *types.Metadata {
	return &k.Metadata
}

func (k *KubernetesCluster) GetRawValue() interface{} {
	return nil
}

func (r *RoleBasedAccessControl) GetMetadata() *types.Metadata {
	return &r.Metadata
}

func (r *RoleBasedAccessControl) GetRawValue() interface{} {
	return nil
}

func (a *AddonProfile) GetMetadata() *types.Metadata {
	return &a.Metadata
}

func (a *AddonProfile) GetRawValue() interface{} {
	return nil
}

func (o *OMSAgent) GetMetadata() *types.Metadata {
	return &o.Metadata
}

func (o *OMSAgent) GetRawValue() interface{} {
	return nil
}

func (n *NetworkProfile) GetMetadata() *types.Metadata {
	return &n.Metadata
}

func (n *NetworkProfile) GetRawValue() interface{} {
	return nil
}
