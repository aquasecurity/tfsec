package ebs

import (
	"github.com/aquasecurity/defsec/provider/aws/ebs"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) ebs.EBS {
	return ebs.EBS{
		Volumes: adaptVolumes(modules),
	}
}

func adaptVolumes(modules block.Modules) []ebs.Volume {
	var volumes []ebs.Volume
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_ebs_volume") {
			volumes = append(volumes, adaptVolume(resource))
		}
	}
	return volumes
}

func adaptVolume(resource *block.Block) ebs.Volume {
	encryptedAttr := resource.GetAttribute("encrypted")
	encryptedVal := encryptedAttr.AsBoolValueOrDefault(false, resource)

	kmsKeyAttr := resource.GetAttribute("kms_key_id")
	kmsKeyVal := kmsKeyAttr.AsStringValueOrDefault("", resource)

	return ebs.Volume{
		Metadata: *resource.GetMetadata(),
		Encryption: ebs.Encryption{
			Metadata: resource.Metadata(),
			Enabled:  encryptedVal,
			KMSKeyID: kmsKeyVal,
		},
	}
}
