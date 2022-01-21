package gke

import (
	"github.com/aquasecurity/defsec/provider/google/gke"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/google/uuid"
	"github.com/zclconf/go-cty/cty"
)

func Adapt(modules block.Modules) gke.GKE {
	return gke.GKE{
		Clusters: (&adapter{
			modules:    modules,
			clusterMap: make(map[string]gke.Cluster),
		}).adaptClusters(),
	}
}

type adapter struct {
	modules    block.Modules
	clusterMap map[string]gke.Cluster
}

func (a *adapter) adaptClusters() []gke.Cluster {
	for _, module := range a.modules {
		for _, resource := range module.GetResourcesByType("google_container_cluster") {
			a.adaptCluster(resource, module)
		}
	}

	a.adaptNodePools()

	for id, cluster := range a.clusterMap {
		if len(cluster.NodePools) > 0 {
			cluster.NodeConfig = cluster.NodePools[0].NodeConfig
			a.clusterMap[id] = cluster
		}
	}

	var clusters []gke.Cluster
	for _, cluster := range a.clusterMap {
		clusters = append(clusters, cluster)
	}
	return clusters
}

func (a *adapter) adaptCluster(resource block.Block, module block.Module) {

	ipAllocationEnabled := types.BoolDefault(false, *resource.GetMetadata())
	networkPolicyEnabled := types.BoolDefault(false, *resource.GetMetadata())
	privateNodesEnabled := types.BoolDefault(false, *resource.GetMetadata())
	podSecurityEnabled := types.BoolDefault(false, *resource.GetMetadata())
	legacyEndpointsEnabled := types.BoolDefault(true, *resource.GetMetadata())

	nodeConfig := gke.NodeConfig{
		ImageType: types.StringDefault("", *resource.GetMetadata()),
		WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
			NodeMetadata: types.StringDefault("", *resource.GetMetadata()),
		},
		ServiceAccount: types.StringDefault("", *resource.GetMetadata()),
	}

	masterAuth := gke.MasterAuth{
		ClientCertificate: gke.ClientCertificate{
			IssueCertificate: types.BoolDefault(false, *resource.GetMetadata()),
		},
		Username: types.StringDefault("", *resource.GetMetadata()),
		Password: types.StringDefault("", *resource.GetMetadata()),
	}

	masterAuthNetworks := gke.MasterAuthorizedNetworks{
		Enabled: types.BoolDefault(false, *resource.GetMetadata()),
		CIDRs:   []types.StringValue{},
	}

	resourceLabelsVal := types.MapDefault(make(map[string]string), resource.GetMetadata())

	if resource.HasChild("ip_allocation_policy") {
		ipAllocationEnabled = types.Bool(true, *resource.GetMetadata())
		if resource.GetBlock("ip_allocation_policy").IsNotNil() {
			ipAllocationEnabled = types.Bool(true, *resource.GetBlock("ip_allocation_policy").GetMetadata())
		}
	}

	if resource.HasChild("master_authorized_networks_config") {
		masterAuthNetworks = adaptMasterAuthNetworks(resource.GetAttribute("master_authorized_networks_config"))
	}

	if resource.HasChild("network_policy") {
		enabledAttr := resource.GetBlock("network_policy").GetAttribute("enabled")
		networkPolicyEnabled = enabledAttr.AsBoolValueOrDefault(false, resource.GetBlock("network_policy"))
	}

	if resource.HasChild("private_cluster_config") {
		privateNodesEnabledAttr := resource.GetBlock("private_cluster_config").GetAttribute("enable_private_nodes")
		privateNodesEnabled = privateNodesEnabledAttr.AsBoolValueOrDefault(false, resource.GetBlock("private_cluster_config"))
	}

	loggingAttr := resource.GetAttribute("logging_service")
	loggingService := loggingAttr.AsStringValueOrDefault("logging.googleapis.com/kubernetes", resource)

	monitoringServiceAttr := resource.GetAttribute("monitoring_service")
	monitoringService := monitoringServiceAttr.AsStringValueOrDefault("monitoring.googleapis.com/kubernetes", resource)

	if resource.HasChild("pod_security_policy_config") {
		enabledAttr := resource.GetBlock("pod_security_policy_config").GetAttribute("enabled")
		podSecurityEnabled = enabledAttr.AsBoolValueOrDefault(false, resource.GetBlock("pod_security_policy_config"))
	}

	legacyMetadataAttr := resource.GetNestedAttribute("metadata.disable-legacy-endpoints")
	if legacyMetadataAttr.IsNotNil() && legacyMetadataAttr.IsTrue() {
		legacyEndpointsEnabled = types.Bool(false, *legacyMetadataAttr.GetMetadata())
	}

	if resource.HasChild("master_auth") && resource.GetBlock("master_auth").IsNotNil() {
		masterAuth = adaptMasterAuth(resource.GetBlock("master_auth"))
	}

	if resource.HasChild("node_config") {
		nodeConfig = adaptNodeConfig(resource.GetBlock("node_config"))
	}

	enableShieldedNodes := resource.GetAttribute("enable_shielded_nodes").AsBoolValueOrDefault(true, resource)

	enableLegacyABACAttr := resource.GetAttribute("enable_legacy_abac")
	enableLegacyABAC := enableLegacyABACAttr.AsBoolValueOrDefault(false, resource)

	resourceLabelsAttr := resource.GetAttribute("resource_labels")
	if resourceLabelsAttr.IsNotNil() {
		resourceLabels := make(map[string]string)

		resourceLabelsAttr.Each(func(key, val cty.Value) {
			resourceLabels[string(key.AsString())] = val.AsString()
		})
		resourceLabelsVal = types.Map(resourceLabels, resourceLabelsAttr.GetMetadata())
	}

	removeDefaultNodePool := resource.GetAttribute("remove_default_node_pool").AsBoolValueOrDefault(false, resource)

	a.clusterMap[resource.ID()] = gke.Cluster{
		Metadata: resource.Metadata(),
		IPAllocationPolicy: gke.IPAllocationPolicy{
			Enabled: ipAllocationEnabled,
		},
		MasterAuthorizedNetworks: masterAuthNetworks,
		NetworkPolicy: gke.NetworkPolicy{
			Enabled: networkPolicyEnabled,
		},
		PrivateCluster: gke.PrivateCluster{
			EnablePrivateNodes: privateNodesEnabled,
		},
		LoggingService:    loggingService,
		MonitoringService: monitoringService,
		PodSecurityPolicy: gke.PodSecurityPolicy{
			Enabled: podSecurityEnabled,
		},
		ClusterMetadata: gke.Metadata{
			EnableLegacyEndpoints: legacyEndpointsEnabled,
		},
		MasterAuth:            masterAuth,
		NodeConfig:            nodeConfig,
		EnableShieldedNodes:   enableShieldedNodes,
		EnableLegacyABAC:      enableLegacyABAC,
		ResourceLabels:        resourceLabelsVal,
		RemoveDefaultNodePool: removeDefaultNodePool,
	}
}

func (a *adapter) adaptNodePools() {
	for _, nodePoolBlock := range a.modules.GetResourcesByType("google_container_node_pool") {
		a.adaptNodePool(nodePoolBlock)
	}
}

func (a *adapter) adaptNodePool(resource block.Block) {
	autoRepair := types.BoolDefault(false, *resource.GetMetadata())
	autoUpgrade := types.BoolDefault(false, *resource.GetMetadata())

	nodeConfig := gke.NodeConfig{
		ImageType: types.StringDefault("", *resource.GetMetadata()),
		WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
			NodeMetadata: types.StringDefault("", *resource.GetMetadata()),
		},
		ServiceAccount: types.StringDefault("", *resource.GetMetadata()),
	}

	if resource.HasChild("management") {
		autoRepairAttr := resource.GetBlock("management").GetAttribute("auto_repair")
		autoRepair = autoRepairAttr.AsBoolValueOrDefault(false, resource.GetBlock("management"))

		autoUpgradeAttr := resource.GetBlock("management").GetAttribute("auto_upgrade")
		autoUpgrade = autoUpgradeAttr.AsBoolValueOrDefault(false, resource.GetBlock("management"))
	}

	if resource.HasChild("node_config") {
		nodeConfig = adaptNodeConfig(resource.GetBlock("node_config"))
	}

	nodePool := gke.NodePool{
		Management: gke.Management{
			EnableAutoRepair:  autoRepair,
			EnableAutoUpgrade: autoUpgrade,
		},
		NodeConfig: nodeConfig,
	}

	clusterAttr := resource.GetAttribute("cluster")
	if referencedCluster, err := a.modules.GetReferencedBlock(clusterAttr, resource); err == nil {
		if referencedCluster.TypeLabel() == "google_container_cluster" {
			if cluster, ok := a.clusterMap[referencedCluster.ID()]; ok {
				cluster.NodePools = append(cluster.NodePools, nodePool)
				a.clusterMap[referencedCluster.ID()] = cluster
				return
			}
		}
	}

	// we didn't find a cluster to put the nodepool in, so create a placeholder
	a.clusterMap[uuid.NewString()] = gke.Cluster{
		NodePools: []gke.NodePool{nodePool},
	}
}

func adaptNodeConfig(resource block.Block) gke.NodeConfig {
	imageTypeAttr := resource.GetAttribute("image_type")
	imageType := imageTypeAttr.AsStringValueOrDefault("", resource)

	modeAttr := resource.GetNestedAttribute("workload_metadata_config.node_metadata")
	if modeAttr.IsNil() {
		modeAttr = resource.GetNestedAttribute("workload_metadata_config.mode") // try newest version
	}
	nodeMetadata := modeAttr.AsStringValueOrDefault("UNSPECIFIED", resource)

	serviceAcc := resource.GetAttribute("service_account").AsStringValueOrDefault("", resource)

	return gke.NodeConfig{
		ImageType: imageType,
		WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
			NodeMetadata: nodeMetadata,
		},
		ServiceAccount: serviceAcc,
	}
}

func adaptMasterAuth(resource block.Block) gke.MasterAuth {
	issueClientCert := types.BoolDefault(false, *resource.GetMetadata())

	if resource.HasChild("client_certificate_config") {
		clientCertAttr := resource.GetBlock("client_certificate_config").GetAttribute("issue_client_certificate")
		issueClientCert = clientCertAttr.AsBoolValueOrDefault(false, resource.GetBlock("client_certificate_config"))
	}

	username := resource.GetAttribute("username").AsStringValueOrDefault("", resource)
	password := resource.GetAttribute("password").AsStringValueOrDefault("", resource)

	return gke.MasterAuth{
		ClientCertificate: gke.ClientCertificate{
			IssueCertificate: issueClientCert,
		},
		Username: username,
		Password: password,
	}
}

func adaptMasterAuthNetworks(attribute block.Attribute) gke.MasterAuthorizedNetworks {
	var cidrs []types.StringValue

	attribute.Each(func(_ cty.Value, val cty.Value) {
		m := val.AsValueMap()
		blocks, ok := m["cidr_blocks"]
		if !ok {
			return
		}
		for _, block := range blocks.AsValueSlice() {
			blockObj := block.AsValueMap()
			cidrBlock, ok := blockObj["cidr_block"]
			if !ok {
				continue
			}
			cidrs = append(cidrs, types.String(cidrBlock.AsString(), *attribute.GetMetadata()))
		}
	})
	enabled := types.Bool(true, *attribute.GetMetadata())

	return gke.MasterAuthorizedNetworks{
		Enabled: enabled,
		CIDRs:   cidrs,
	}
}
