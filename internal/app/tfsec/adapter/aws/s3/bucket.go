package s3

import (
	"github.com/aquasecurity/defsec/provider/aws/s3"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func getBuckets(modules block.Modules) []s3.Bucket {
	var buckets []s3.Bucket
	blocks := modules.GetBlocksByTypeLabel("aws_s3_bucket")
	for _, b := range blocks {
		func(block block.Block) {
			s3b := s3.Bucket{
				Name:     getName(block),
				Metadata: types.NewMetadata(block.Range()).WithReference(block.Reference()),
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
			}

			buckets = append(buckets, s3b)

		}(b)
	}

	return buckets
}

func getName(b block.Block) types.StringValue {
	if nameAttr := b.GetAttribute("bucket"); nameAttr.IsString() {
		return types.StringValue{
			Metadata: types.NewMetadata(nameAttr.Range()),
			Value:    nameAttr.Value().AsString(),
		}
	}
	return types.StringValue{
		Metadata: types.NewMetadata(b.Range()),
		Value:    "",
	}

}

func getACL(b block.Block) types.StringValue {
	if aclAttr := b.GetAttribute("acl"); aclAttr.IsString() {
		return types.StringValue{
			Metadata: types.NewMetadata(aclAttr.Range()),
			Value:    aclAttr.Value().AsString(),
		}
	}
	return types.StringValue{
		Metadata: types.NewMetadata(b.Range()),
		Value:    "private",
	}
}

func isEncrypted(b block.Block) types.BoolValue {
	encryptionBlock := b.GetBlock("server_side_encryption_configuration")
	if encryptionBlock.IsNil() {
		return types.BoolValue{
			Metadata: types.NewMetadata(b.Range()),
			Value:    false,
		}
	}
	ruleBlock := encryptionBlock.GetBlock("rule")
	if ruleBlock.IsNil() {
		return types.BoolValue{
			Metadata: types.NewMetadata(encryptionBlock.Range()),
			Value:    false,
		}

	}
	if defaultBlock := ruleBlock.GetBlock("apply_server_side_encryption_by_default"); defaultBlock.IsNil() {
		return types.BoolValue{
			Metadata: types.NewMetadata(ruleBlock.Range()),
			Value:    false,
		}
	} else {
		return types.BoolValue{
			Metadata: types.NewMetadata(defaultBlock.Range()),
			Value:    true,
		}

	}
}

func hasLogging(b block.Block) types.BoolValue {
	if loggingBlock := b.GetBlock("logging"); loggingBlock.IsNotNil() {
		if targetAttr := loggingBlock.GetAttribute("target_bucket"); targetAttr.IsNotNil() {
			return types.BoolValue{
				Metadata: types.NewMetadata(targetAttr.Range()),
				Value:    targetAttr.IsNotEmpty(),
			}
		}
		return types.BoolValue{
			Metadata: types.NewMetadata(loggingBlock.Range()),
			Value:    false,
		}
	}
	return types.BoolValue{
		Metadata: types.NewMetadata(b.Range()),
		Value:    false,
	}
}

func isVersioned(b block.Block) types.BoolValue {
	if versioningBlock := b.GetBlock("versioning"); versioningBlock.IsNotNil() {
		if enabledAttr := versioningBlock.GetAttribute("enabled"); enabledAttr.IsNotNil() {
			return types.BoolValue{
				Metadata: types.NewMetadata(enabledAttr.Range()),
				Value:    enabledAttr.IsTrue(),
			}
		}
		return types.BoolValue{
			Metadata: types.NewMetadata(versioningBlock.Range()),
			Value:    true,
		}
	}
	return types.BoolValue{
		Metadata: types.NewMetadata(b.Range()),
		Value:    false,
	}
}

func AttributeToBoolValue(attribute block.Attribute, block block.Block, defaultValue bool) types.BoolValue {

	if attribute.IsNil() {
		return types.BoolValue{
			Metadata: types.NewMetadata(block.Range()),
			Value:    defaultValue,
		}
	}

	return types.BoolValue{
		Metadata: types.NewMetadata(attribute.Range()),
		Value:    attribute.IsTrue(),
	}

}
