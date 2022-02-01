package eks

import (
	"github.com/aquasecurity/defsec/provider/aws/eks"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) eks.EKS {
	return eks.EKS{
		Clusters: adaptClusters(modules),
	}
}

func adaptClusters(modules block.Modules) []eks.Cluster {
	var clusters []eks.Cluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_eks_cluster") {
			clusters = append(clusters, adaptCluster(resource))
		}
	}
	return clusters
}

func adaptCluster(resource *block.Block) eks.Cluster {

	cluster := eks.Cluster{
		Metadata: resource.Metadata(),
		Logging: eks.Logging{
			Metadata:          resource.Metadata(),
			API:               types.BoolDefault(false, resource.Metadata()),
			Audit:             types.BoolDefault(false, resource.Metadata()),
			Authenticator:     types.BoolDefault(false, resource.Metadata()),
			ControllerManager: types.BoolDefault(false, resource.Metadata()),
			Scheduler:         types.BoolDefault(false, resource.Metadata()),
		},
		Encryption: eks.Encryption{
			Metadata: resource.Metadata(),
			Secrets:  types.BoolDefault(false, resource.Metadata()),
			KMSKeyID: types.StringDefault("", resource.Metadata()),
		},
		PublicAccessEnabled: types.BoolDefault(true, resource.Metadata()),
		PublicAccessCIDRs:   nil,
	}

	if logTypesAttr := resource.GetAttribute("enabled_cluster_log_types"); logTypesAttr.IsNotNil() {
		cluster.Logging.Metadata = logTypesAttr.Metadata()
		logTypesList := logTypesAttr.ValueAsStrings()
		for _, logType := range logTypesList {
			switch logType {
			case "api":
				cluster.Logging.API = types.Bool(true, logTypesAttr.Metadata())
			case "audit":
				cluster.Logging.Audit = types.Bool(true, logTypesAttr.Metadata())
			case "authenticator":
				cluster.Logging.Authenticator = types.Bool(true, logTypesAttr.Metadata())
			case "controllerManager":
				cluster.Logging.ControllerManager = types.Bool(true, logTypesAttr.Metadata())
			case "scheduler":
				cluster.Logging.Scheduler = types.Bool(true, logTypesAttr.Metadata())
			}
		}
	}

	if encryptBlock := resource.GetBlock("encryption_config"); encryptBlock.IsNotNil() {
		cluster.Encryption.Metadata = encryptBlock.Metadata()
		resourcesAttr := encryptBlock.GetAttribute("resources")
		if resourcesAttr.Contains("secrets") {
			cluster.Encryption.Secrets = types.Bool(true, resourcesAttr.Metadata())
		}
		if providerBlock := encryptBlock.GetBlock("provider"); providerBlock.IsNotNil() {
			keyArnAttr := providerBlock.GetAttribute("key_arn")
			cluster.Encryption.KMSKeyID = keyArnAttr.AsStringValueOrDefault("", providerBlock)
		}
	}

	if vpcBlock := resource.GetBlock("vpc_config"); vpcBlock.IsNotNil() {
		publicAccessAttr := vpcBlock.GetAttribute("endpoint_public_access")
		cluster.PublicAccessEnabled = publicAccessAttr.AsBoolValueOrDefault(true, vpcBlock)

		publicAccessCidrsAttr := vpcBlock.GetAttribute("public_access_cidrs")
		cidrsList := publicAccessCidrsAttr.ValueAsStrings()
		for _, cidr := range cidrsList {
			cluster.PublicAccessCIDRs = append(cluster.PublicAccessCIDRs, types.String(cidr, publicAccessCidrsAttr.Metadata()))
		}
		if len(cidrsList) == 0 {
			cluster.PublicAccessCIDRs = append(cluster.PublicAccessCIDRs, types.StringDefault("0.0.0.0/0", vpcBlock.Metadata()))
		}
	}

	return cluster
}
