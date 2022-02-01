package cloudtrail

import (
	"github.com/aquasecurity/defsec/provider/aws/cloudtrail"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) cloudtrail.CloudTrail {
	return cloudtrail.CloudTrail{
		Trails: adaptTrails(modules),
	}
}

func adaptTrails(modules block.Modules) []cloudtrail.Trail {
	var trails []cloudtrail.Trail

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_cloudtrail") {
			trails = append(trails, adaptTrail(resource))
		}
	}
	return trails
}

func adaptTrail(resource *block.Block) cloudtrail.Trail {
	nameAttr := resource.GetAttribute("name")
	nameVal := nameAttr.AsStringValueOrDefault("", resource)

	enableLogFileValidationAttr := resource.GetAttribute("enable_log_file_validation")
	enableLogFileValidationVal := enableLogFileValidationAttr.AsBoolValueOrDefault(false, resource)

	isMultiRegionAttr := resource.GetAttribute("is_multi_region_trail")
	isMultiRegionVal := isMultiRegionAttr.AsBoolValueOrDefault(false, resource)

	KMSKeyIDAttr := resource.GetAttribute("kms_key_id")
	KMSKeyIDVal := KMSKeyIDAttr.AsStringValueOrDefault("", resource)

	return cloudtrail.Trail{
		Metadata:                resource.Metadata(),
		Name:                    nameVal,
		EnableLogFileValidation: enableLogFileValidationVal,
		IsMultiRegion:           isMultiRegionVal,
		KMSKeyID:                KMSKeyIDVal,
	}
}
