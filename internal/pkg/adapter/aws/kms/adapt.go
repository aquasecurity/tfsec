package kms

import (
	"github.com/aquasecurity/defsec/provider/aws/kms"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) kms.KMS {
	return kms.KMS{
		Keys: adaptKeys(modules),
	}
}

func adaptKeys(modules block.Modules) []kms.Key {
	var keys []kms.Key
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_kms_key") {
			keys = append(keys, adaptKey(resource))
		}
	}
	return keys
}

func adaptKey(resource *block.Block) kms.Key {
	usageAttr := resource.GetAttribute("key_usage")
	usageVal := usageAttr.AsStringValueOrDefault("ENCRYPT_DECRYPT", resource)

	enableKeyRotationAttr := resource.GetAttribute("enable_key_rotation")
	enableKeyRotationVal := enableKeyRotationAttr.AsBoolValueOrDefault(false, resource)

	return kms.Key{
		Metadata:        resource.Metadata(),
		Usage:           usageVal,
		RotationEnabled: enableKeyRotationVal,
	}
}
