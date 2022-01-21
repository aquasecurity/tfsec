package container

import (
	"github.com/aquasecurity/defsec/provider/azure/container"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules block.Modules) container.Container {
	return container.Container{
		KubernetesClusters: adaptClusters(modules),
	}
}

func adaptClusters(modules block.Modules) []container.KubernetesCluster {
	var clusters []container.KubernetesCluster

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_kubernetes_cluster") {
			clusters = append(clusters, adaptCluster(resource))
		}
	}
	return clusters
}

func adaptCluster(resource *block.Block) container.KubernetesCluster {

	networkProfileBlock := resource.GetBlock("network_profile")
	networkPolicyVal := types.StringDefault("", resource.Metadata())

	if networkProfileBlock.IsNotNil() {
		networkPolicyAttr := networkProfileBlock.GetAttribute("network_policy")
		networkPolicyVal = networkPolicyAttr.AsStringValueOrDefault("", networkProfileBlock)
	}

	privateClusterEnabledAttr := resource.GetAttribute("private_cluster_enabled")
	privateClusterEnabledVal := privateClusterEnabledAttr.AsBoolValueOrDefault(false, resource)

	apiServerAuthorizedIPRangesAttr := resource.GetAttribute("api_server_authorized_ip_ranges")
	ips := apiServerAuthorizedIPRangesAttr.ValueAsStrings()
	authIPRangesVals := []types.StringValue{}
	for _, ip := range ips {
		authIPRangesVals = append(authIPRangesVals, types.String(ip, *resource.GetMetadata()))
	}

	enabledVal := types.Bool(false, *resource.GetMetadata())
	addonProfileBlock := resource.GetBlock("addon_profile")
	if addonProfileBlock.IsNotNil() {
		omsAgentBlock := addonProfileBlock.GetBlock("oms_agent")
		if omsAgentBlock.IsNotNil() {
			enabledAttr := omsAgentBlock.GetAttribute("enabled")
			enabledVal = enabledAttr.AsBoolValueOrDefault(false, omsAgentBlock)
		}
	}

	roleBasedAccessControlBlock := resource.GetBlock("role_based_access_control")
	rbEnabledVal := types.Bool(false, *resource.GetMetadata())

	if roleBasedAccessControlBlock.IsNotNil() {
		rbEnabledAttr := roleBasedAccessControlBlock.GetAttribute("enabled")
		rbEnabledVal = rbEnabledAttr.AsBoolValueOrDefault(false, roleBasedAccessControlBlock)
	}
	return container.KubernetesCluster{
		Metadata: resource.Metadata(),
		NetworkProfile: container.NetworkProfile{
			NetworkPolicy: networkPolicyVal,
		},
		EnablePrivateCluster:        privateClusterEnabledVal,
		APIServerAuthorizedIPRanges: authIPRangesVals,
		AddonProfile: container.AddonProfile{
			OMSAgent: container.OMSAgent{
				Enabled: enabledVal,
			},
		},
		RoleBasedAccessControl: container.RoleBasedAccessControl{
			Enabled: rbEnabledVal,
		},
	}

}
