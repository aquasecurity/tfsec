package container

import "github.com/aquasecurity/defsec/types"

type Container struct {
	KubernetesClusters []KubernetesCluster
}

type KubernetesCluster struct {
	NetworkProfile              NetworkProfile
	EnablePrivateCluster        types.BoolValue
	APIServerAuthorizedIPRanges []types.StringValue
	AddonProfile                AddonProfile
	RoleBasedAccessControl      RoleBasedAccessControl
}

type RoleBasedAccessControl struct {
	Enabled types.BoolValue
}

type AddonProfile struct {
	OMSAgent OMSAgent
}

type OMSAgent struct {
	Enabled types.BoolValue
}

type NetworkProfile struct {
	NetworkPolicy types.StringValue // "", "calico", "azure"
}
