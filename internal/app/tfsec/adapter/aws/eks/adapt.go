package eks

import (
	"github.com/aquasecurity/defsec/provider/aws/eks"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) eks.EKS {
	return eks.EKS{
		Clusters: adaptClusters(modules),
	}
}

func adaptClusters(modules []block.Module) []eks.Cluster {
	var clusters []eks.Cluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_eks_cluster") {
			clusters = append(clusters, adaptCluster(resource))
		}
	}
	return clusters
}

func adaptCluster(resource block.Block) eks.Cluster {
	logging := eks.Logging{
		API:               types.BoolDefault(false, *resource.GetMetadata()),
		Audit:             types.BoolDefault(false, *resource.GetMetadata()),
		Authenticator:     types.BoolDefault(false, *resource.GetMetadata()),
		ControllerManager: types.BoolDefault(false, *resource.GetMetadata()),
		Scheduler:         types.BoolDefault(false, *resource.GetMetadata()),
	}

	logTypesAttr := resource.GetAttribute("enabled_cluster_log_types")
	logTypesList := logTypesAttr.ValueAsStrings()
	for _, logType := range logTypesList {
		switch logType {
		case "api":
			logging.API = types.Bool(true, *logTypesAttr.GetMetadata())
		case "audit":
			logging.Audit = types.Bool(true, *logTypesAttr.GetMetadata())
		case "authenticator":
			logging.Authenticator = types.Bool(true, *logTypesAttr.GetMetadata())
		case "controllerManager":
			logging.ControllerManager = types.Bool(true, *logTypesAttr.GetMetadata())
		case "scheduler":
			logging.Scheduler = types.Bool(true, *logTypesAttr.GetMetadata())
		}
	}

	secrets := types.BoolDefault(false, *resource.GetMetadata())
	keyArnVal := types.StringDefault("", *resource.GetMetadata())

	if resource.HasChild("encryption_config") {
		encryptBlock := resource.GetBlock("encryption_config")
		resourcesAttr := encryptBlock.GetAttribute("resources")
		if resourcesAttr.Contains("secrets") {
			secrets = types.Bool(true, *resourcesAttr.GetMetadata())
		}
		if encryptBlock.HasChild("provider") {
			providerBlock := encryptBlock.GetBlock("provider")
			keyArnAttr := providerBlock.GetAttribute("key_arn")
			keyArnVal = keyArnAttr.AsStringValueOrDefault("", providerBlock)
		}
	}

	publicAccessVal := types.BoolDefault(true, *resource.GetMetadata())
	var cidrs []types.StringValue

	if resource.HasChild("vpc_config") {
		vpcBlock := resource.GetBlock("vpc_config")
		publicAccessAttr := vpcBlock.GetAttribute("endpoint_public_access")
		publicAccessVal = publicAccessAttr.AsBoolValueOrDefault(true, vpcBlock)

		publicAccessCidrsAttr := resource.GetAttribute("public_access_cidrs")
		cidrsList := publicAccessCidrsAttr.ValueAsStrings()
		for _, cidr := range cidrsList {
			cidrs = append(cidrs, types.String(cidr, *publicAccessCidrsAttr.GetMetadata()))
		}
		if len(cidrsList) == 0 {
			cidrs = append(cidrs, types.StringDefault("0.0.0.0/0", *vpcBlock.GetMetadata()))
		}

	}

	return eks.Cluster{
		Metadata: *resource.GetMetadata(),
		Logging:  logging,
		Encryption: eks.Encryption{
			Secrets:  secrets,
			KMSKeyID: keyArnVal,
		},
		PublicAccessEnabled: publicAccessVal,
		PublicAccessCIDRs:   cidrs,
	}
}
