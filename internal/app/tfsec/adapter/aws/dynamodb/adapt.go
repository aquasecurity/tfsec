package dynamodb

import (
	"github.com/aquasecurity/defsec/provider/aws/dynamodb"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
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
	sseEnabledVal := types.BoolDefault(false, *resource.GetMetadata())
	kmsKeyIdVal := types.StringDefault("", *resource.GetMetadata())
	recoveryEnabledVal := types.BoolDefault(false, *resource.GetMetadata())

	if resource.HasChild("server_side_encryption") {
		ssEncryptionBlock := resource.GetBlock("server_side_encryption")
		enabledAttr := ssEncryptionBlock.GetAttribute("enabled")
		sseEnabledVal = enabledAttr.AsBoolValueOrDefault(false, ssEncryptionBlock)

		if resource.TypeLabel() == "aws_dynamodb_table" {
			kmsKeyIdAttr := ssEncryptionBlock.GetAttribute("kms_key_arn")

			kmsData, err := module.GetReferencedBlock(kmsKeyIdAttr, resource)
			if err == nil && kmsData.IsNotNil() && kmsData.GetAttribute("key_id").IsNotNil() {
				kmsKeyIdAttr = kmsData.GetAttribute("key_id")
			}

			kmsKeyIdVal = kmsKeyIdAttr.AsStringValueOrDefault("alias/aws/dynamodb", ssEncryptionBlock)
		}
	}

	if resource.HasChild("point_in_time_recovery") {
		recoveryBlock := resource.GetBlock("point_in_time_recovery")
		recoveryEnabledAttr := recoveryBlock.GetAttribute("enabled")
		recoveryEnabledVal = recoveryEnabledAttr.AsBoolValueOrDefault(false, recoveryBlock)
	}

	return dynamodb.DAXCluster{
		Metadata: *resource.GetMetadata(),
		ServerSideEncryption: dynamodb.ServerSideEncryption{
			Enabled:  sseEnabledVal,
			KMSKeyID: kmsKeyIdVal,
		},
		PointInTimeRecovery: recoveryEnabledVal,
	}

}
