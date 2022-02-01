package neptune

import (
	"github.com/aquasecurity/defsec/provider/aws/neptune"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) neptune.Neptune {
	return neptune.Neptune{
		Clusters: adaptClusters(modules),
	}
}

func adaptClusters(modules block.Modules) []neptune.Cluster {
	var clusters []neptune.Cluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_neptune_cluster") {
			clusters = append(clusters, adaptCluster(resource))
		}
	}
	return clusters
}

func adaptCluster(resource *block.Block) neptune.Cluster {
	cluster := neptune.Cluster{
		Metadata: resource.Metadata(),
		Logging: neptune.Logging{
			Metadata: resource.Metadata(),
			Audit:    types.BoolDefault(false, resource.Metadata()),
		},
		StorageEncrypted: types.BoolDefault(false, resource.Metadata()),
		KMSKeyID:         types.StringDefault("", resource.Metadata()),
	}

	if enableLogExportsAttr := resource.GetAttribute("enable_cloudwatch_logs_exports"); enableLogExportsAttr.IsNotNil() {
		cluster.Logging.Metadata = enableLogExportsAttr.Metadata()
		if enableLogExportsAttr.Contains("audit") {
			cluster.Logging.Audit = types.Bool(true, *resource.GetMetadata())
		}
	}

	storageEncryptedAttr := resource.GetAttribute("storage_encrypted")
	cluster.StorageEncrypted = storageEncryptedAttr.AsBoolValueOrDefault(false, resource)

	KMSKeyAttr := resource.GetAttribute("kms_key_arn")
	cluster.KMSKeyID = KMSKeyAttr.AsStringValueOrDefault("", resource)

	return cluster
}
