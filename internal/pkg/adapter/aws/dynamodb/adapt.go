package dynamodb

import (
	"github.com/aquasecurity/defsec/provider/aws/dynamodb"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) dynamodb.DynamoDB {
	return dynamodb.DynamoDB{
		DAXClusters: adaptClusters(modules),
	}
}

func adaptClusters(modules block.Modules) []dynamodb.DAXCluster {
	var clusters []dynamodb.DAXCluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_dax_cluster") {
			clusters = append(clusters, adaptCluster(resource, module))
		}
		for _, resource := range module.GetResourcesByType("aws_dynamodb_table") {
			clusters = append(clusters, adaptCluster(resource, module))
		}
	}
	return clusters
}

func adaptCluster(resource *block.Block, module *block.Module) dynamodb.DAXCluster {

	cluster := dynamodb.DAXCluster{
		Metadata: resource.Metadata(),
		ServerSideEncryption: dynamodb.ServerSideEncryption{
			Metadata: resource.Metadata(),
			Enabled:  types.BoolDefault(false, resource.Metadata()),
			KMSKeyID: types.StringDefault("", resource.Metadata()),
		},
		PointInTimeRecovery: types.BoolDefault(false, resource.Metadata()),
	}

	if ssEncryptionBlock := resource.GetBlock("server_side_encryption"); ssEncryptionBlock.IsNotNil() {
		cluster.Metadata = ssEncryptionBlock.Metadata()
		enabledAttr := ssEncryptionBlock.GetAttribute("enabled")
		cluster.ServerSideEncryption.Enabled = enabledAttr.AsBoolValueOrDefault(false, ssEncryptionBlock)

		if resource.TypeLabel() == "aws_dynamodb_table" {
			kmsKeyIdAttr := ssEncryptionBlock.GetAttribute("kms_key_arn")

			kmsData, err := module.GetReferencedBlock(kmsKeyIdAttr, resource)
			if err == nil && kmsData.IsNotNil() && kmsData.GetAttribute("key_id").IsNotNil() {
				kmsKeyIdAttr = kmsData.GetAttribute("key_id")
			}

			cluster.ServerSideEncryption.KMSKeyID = kmsKeyIdAttr.AsStringValueOrDefault("alias/aws/dynamodb", ssEncryptionBlock)
		}
	}

	if recoveryBlock := resource.GetBlock("point_in_time_recovery"); recoveryBlock.IsNotNil() {
		recoveryEnabledAttr := recoveryBlock.GetAttribute("enabled")
		cluster.PointInTimeRecovery = recoveryEnabledAttr.AsBoolValueOrDefault(false, recoveryBlock)
	}

	return cluster
}
