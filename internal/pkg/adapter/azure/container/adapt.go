package container

import (
	"github.com/aquasecurity/defsec/provider/azure/container"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
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

	cluster := container.KubernetesCluster{
		Metadata: resource.Metadata(),
		NetworkProfile: container.NetworkProfile{
			Metadata:      resource.Metadata(),
			NetworkPolicy: types.StringDefault("", resource.Metadata()),
		},
		EnablePrivateCluster:        types.BoolDefault(false, resource.Metadata()),
		APIServerAuthorizedIPRanges: nil,
		RoleBasedAccessControl: container.RoleBasedAccessControl{
			Metadata: resource.Metadata(),
			Enabled:  types.BoolDefault(false, resource.Metadata()),
		},
		AddonProfile: container.AddonProfile{
			Metadata: resource.Metadata(),
			OMSAgent: container.OMSAgent{
				Metadata: resource.Metadata(),
				Enabled:  types.BoolDefault(false, resource.Metadata()),
			},
		},
	}
	cluster.Metadata = resource.Metadata()

	networkProfileBlock := resource.GetBlock("network_profile")
	if networkProfileBlock.IsNotNil() {
		networkPolicyAttr := networkProfileBlock.GetAttribute("network_policy")
		cluster.NetworkProfile.Metadata = networkProfileBlock.Metadata()
		cluster.NetworkProfile.NetworkPolicy = networkPolicyAttr.AsStringValueOrDefault("", networkProfileBlock)
	}

	privateClusterEnabledAttr := resource.GetAttribute("private_cluster_enabled")
	cluster.EnablePrivateCluster = privateClusterEnabledAttr.AsBoolValueOrDefault(false, resource)

	apiServerAuthorizedIPRangesAttr := resource.GetAttribute("api_server_authorized_ip_ranges")
	ips := apiServerAuthorizedIPRangesAttr.ValueAsStrings()
	for _, ip := range ips {
		cluster.APIServerAuthorizedIPRanges = append(cluster.APIServerAuthorizedIPRanges, types.String(ip, resource.Metadata()))
	}

	addonProfileBlock := resource.GetBlock("addon_profile")
	if addonProfileBlock.IsNotNil() {
		cluster.AddonProfile.Metadata = addonProfileBlock.Metadata()
		omsAgentBlock := addonProfileBlock.GetBlock("oms_agent")
		if omsAgentBlock.IsNotNil() {
			cluster.AddonProfile.OMSAgent.Metadata = omsAgentBlock.Metadata()
			enabledAttr := omsAgentBlock.GetAttribute("enabled")
			cluster.AddonProfile.OMSAgent.Enabled = enabledAttr.AsBoolValueOrDefault(false, omsAgentBlock)
		}
	}

	roleBasedAccessControlBlock := resource.GetBlock("role_based_access_control")
	if roleBasedAccessControlBlock.IsNotNil() {
		rbEnabledAttr := roleBasedAccessControlBlock.GetAttribute("enabled")
		cluster.RoleBasedAccessControl.Metadata = roleBasedAccessControlBlock.Metadata()
		cluster.RoleBasedAccessControl.Enabled = rbEnabledAttr.AsBoolValueOrDefault(false, roleBasedAccessControlBlock)
	}
	return cluster
}
