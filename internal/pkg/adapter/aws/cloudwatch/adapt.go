package cloudwatch

import (
	"github.com/aquasecurity/defsec/provider/aws/cloudwatch"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) cloudwatch.CloudWatch {
	return cloudwatch.CloudWatch{
		LogGroups: adaptLogGroups(modules),
	}
}

func adaptLogGroups(modules block.Modules) []cloudwatch.LogGroup {
	var logGroups []cloudwatch.LogGroup
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_cloudwatch_log_group") {
			logGroups = append(logGroups, adaptLogGroup(resource))
		}
	}
	return logGroups
}

func adaptLogGroup(resource *block.Block) cloudwatch.LogGroup {
	nameAttr := resource.GetAttribute("name")
	nameVal := nameAttr.AsStringValueOrDefault("", resource)

	KMSKeyIDAttr := resource.GetAttribute("kms_key_id")
	KMSKeyIDVal := KMSKeyIDAttr.AsStringValueOrDefault("", resource)

	retentionInDaysAttr := resource.GetAttribute("retention_in_days")
	retentionInDaysVal := retentionInDaysAttr.AsIntValueOrDefault(0, resource)

	return cloudwatch.LogGroup{
		Metadata:        resource.Metadata(),
		Name:            nameVal,
		KMSKeyID:        KMSKeyIDVal,
		RetentionInDays: retentionInDaysVal,
	}
}
