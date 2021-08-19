package s3

import (
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/pkg/defsec/aws/s3"
	"github.com/aquasecurity/tfsec/pkg/defsec/definition"
)

func Adapt(modules []block.Module) s3.S3 {
	return s3.S3{
		Buckets: getBuckets(modules),
	}
}

func getBuckets(modules block.Modules) []s3.Bucket {
	var buckets []s3.Bucket
	blocks := modules.GetBlocksByTypeLabel("aws_s3_bucket")
	for _, b := range blocks {
		func(block block.Block) {
			buckets = append(buckets, s3.Bucket{
				Metadata: definition.NewMetadata(block.Range()).WithReference(block.FullName()),
				Versioning: s3.Versioning{
					Enabled: AttributeToBoolValue(block.GetNestedAttribute("versioning.enabled"), block, false),
				},
				Encryption: s3.BucketEncryption{
					Enabled: isEncrypted(block),
				},
			})
		}(b)
	}

	return buckets
}

func isEncrypted(b block.Block) definition.BoolValue {
	encryptionBlock := b.GetBlock("server_side_encryption_configuration")

	if encryptionBlock.IsNil() {
		return definition.BoolValue{
			Metadata: definition.NewMetadata(b.Range()),
			Value:    false,
		}
	}

	ruleBlock := encryptionBlock.GetBlock("rule")
	if ruleBlock.IsNil() {
		return definition.BoolValue{
			Metadata: definition.NewMetadata(encryptionBlock.Range()),
			Value:    false,
		}

	}

	if defaultBlock := ruleBlock.GetBlock("apply_server_side_encryption_by_default"); defaultBlock.IsNil() {
		return definition.BoolValue{
			Metadata: definition.NewMetadata(ruleBlock.Range()),
			Value:    false,
		}

	} else {
		return definition.BoolValue{
			Metadata: definition.NewMetadata(defaultBlock.Range()),
			Value:    true,
		}

	}

}

func AttributeToBoolValue(attribute block.Attribute, block block.Block, defaultValue bool) definition.BoolValue {

	if attribute.IsNil() {
		return definition.BoolValue{
			Metadata: definition.NewMetadata(block.Range()),
			Value:    defaultValue,
		}
	}

	return definition.BoolValue{
		Metadata: definition.NewMetadata(attribute.Range()),
		Value:    attribute.IsTrue(),
	}

}
