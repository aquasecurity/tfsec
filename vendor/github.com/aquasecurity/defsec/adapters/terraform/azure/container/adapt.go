package container

import (
	"github.com/aquasecurity/defsec/provider/azure/container"
	"github.com/aquasecurity/trivy-config-parsers/terraform"
	"github.com/aquasecurity/trivy-config-parsers/types"
)

func Adapt(modules terraform.Modules) container.Container {
	return container.Container{
		KubernetesClusters: adaptClusters(modules),
	}
}

func adaptClusters(modules terraform.Modules) []container.KubernetesCluster {
	var clusters []container.KubernetesCluster

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_kubernetes_cluster") {
			clusters = append(clusters, adaptCluster(resource))
		}
	}
	return clusters
}

func adaptCluster(resource *terraform.Block) container.KubernetesCluster {

	cluster := container.KubernetesCluster{
		Metadata: resource.GetMetadata(),
		NetworkProfile: container.NetworkProfile{
			Metadata:      resource.GetMetadata(),
			NetworkPolicy: types.StringDefault("", resource.GetMetadata()),
		},
		EnablePrivateCluster:        types.BoolDefault(false, resource.GetMetadata()),
		APIServerAuthorizedIPRanges: nil,
		RoleBasedAccessControl: container.RoleBasedAccessControl{
			Metadata: resource.GetMetadata(),
			Enabled:  types.BoolDefault(false, resource.GetMetadata()),
		},
		AddonProfile: container.AddonProfile{
			Metadata: resource.GetMetadata(),
			OMSAgent: container.OMSAgent{
				Metadata: resource.GetMetadata(),
				Enabled:  types.BoolDefault(false, resource.GetMetadata()),
			},
		},
	}
	cluster.Metadata = resource.GetMetadata()

	networkProfileBlock := resource.GetBlock("network_profile")
	if networkProfileBlock.IsNotNil() {
		networkPolicyAttr := networkProfileBlock.GetAttribute("network_policy")
		cluster.NetworkProfile.Metadata = networkProfileBlock.GetMetadata()
		cluster.NetworkProfile.NetworkPolicy = networkPolicyAttr.AsStringValueOrDefault("", networkProfileBlock)
	}

	privateClusterEnabledAttr := resource.GetAttribute("private_cluster_enabled")
	cluster.EnablePrivateCluster = privateClusterEnabledAttr.AsBoolValueOrDefault(false, resource)

	apiServerAuthorizedIPRangesAttr := resource.GetAttribute("api_server_authorized_ip_ranges")
	ips := apiServerAuthorizedIPRangesAttr.ValueAsStrings()
	for _, ip := range ips {
		cluster.APIServerAuthorizedIPRanges = append(cluster.APIServerAuthorizedIPRanges, types.String(ip, resource.GetMetadata()))
	}

	addonProfileBlock := resource.GetBlock("addon_profile")
	if addonProfileBlock.IsNotNil() {
		cluster.AddonProfile.Metadata = addonProfileBlock.GetMetadata()
		omsAgentBlock := addonProfileBlock.GetBlock("oms_agent")
		if omsAgentBlock.IsNotNil() {
			cluster.AddonProfile.OMSAgent.Metadata = omsAgentBlock.GetMetadata()
			enabledAttr := omsAgentBlock.GetAttribute("enabled")
			cluster.AddonProfile.OMSAgent.Enabled = enabledAttr.AsBoolValueOrDefault(false, omsAgentBlock)
		}
	}

	roleBasedAccessControlBlock := resource.GetBlock("role_based_access_control")
	if roleBasedAccessControlBlock.IsNotNil() {
		rbEnabledAttr := roleBasedAccessControlBlock.GetAttribute("enabled")
		cluster.RoleBasedAccessControl.Metadata = roleBasedAccessControlBlock.GetMetadata()
		cluster.RoleBasedAccessControl.Enabled = rbEnabledAttr.AsBoolValueOrDefault(false, roleBasedAccessControlBlock)
	}
	return cluster
}
