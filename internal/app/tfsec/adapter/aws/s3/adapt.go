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
					Enabled: isVersioned(block),
				},
				Encryption: s3.Encryption{
					Enabled: isEncrypted(block),
				},
				Logging: s3.Logging{
					Enabled: hasLogging(block),
				},
				ACL: getACL(block),
			})
		}(b)
	}

	return buckets
}

func getACL(b block.Block) definition.StringValue {
	if aclAttr := b.GetAttribute("acl"); aclAttr.IsString() {
		return definition.StringValue{
			Metadata: definition.NewMetadata(aclAttr.Range()),
			Value:    aclAttr.Value().AsString(),
		}
	}
	return definition.StringValue{
		Metadata: definition.NewMetadata(b.Range()),
		Value:    "private",
	}
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

func hasLogging(b block.Block) definition.BoolValue {
	if loggingBlock := b.GetBlock("logging"); loggingBlock.IsNotNil() {
		if enabledAttr := loggingBlock.GetAttribute("enabled"); enabledAttr.IsNotNil() {
			return definition.BoolValue{
				Metadata: definition.NewMetadata(enabledAttr.Range()),
				Value:    enabledAttr.IsTrue(),
			}
		}
		return definition.BoolValue{
			Metadata: definition.NewMetadata(loggingBlock.Range()),
			Value:    false,
		}
	}
	return definition.BoolValue{
		Metadata: definition.NewMetadata(b.Range()),
		Value:    false,
	}
}

func isVersioned(b block.Block) definition.BoolValue {
	if versioningBlock := b.GetBlock("versioning"); versioningBlock.IsNotNil() {
		if enabledAttr := versioningBlock.GetAttribute("enabled"); enabledAttr.IsNotNil() {
			return definition.BoolValue{
				Metadata: definition.NewMetadata(enabledAttr.Range()),
				Value:    enabledAttr.IsTrue(),
			}
		}
		return definition.BoolValue{
			Metadata: definition.NewMetadata(versioningBlock.Range()),
			Value:    false,
		}
	}
	return definition.BoolValue{
		Metadata: definition.NewMetadata(b.Range()),
		Value:    false,
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
