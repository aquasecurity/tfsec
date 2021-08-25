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
				Metadata: types.NewMetadata(block.Range(), block.Reference()),
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
		return nameAttr.AsStringValue(true)
	}
	return types.StringDefault(
		"",
		b.Range(),
		b.Reference(),
	)
}

func getACL(b block.Block) types.StringValue {
	if aclAttr := b.GetAttribute("acl"); aclAttr.IsString() {
		return aclAttr.AsStringValue(true)
	}
	return types.StringDefault(
		"",
		b.Range(),
		b.Reference(),
	)
}

func isEncrypted(b block.Block) types.BoolValue {

	encryptionBlock := b.GetBlock("server_side_encryption_configuration")
	if encryptionBlock.IsNil() {
		return types.BoolDefault(false, b.Range(), b.Reference())
	}
	ruleBlock := encryptionBlock.GetBlock("rule")
	if ruleBlock.IsNil() {
		return types.BoolDefault(false, encryptionBlock.Range(), encryptionBlock.Reference())
	}
	defaultBlock := ruleBlock.GetBlock("apply_server_side_encryption_by_default")
	if defaultBlock.IsNil() {
		return types.BoolDefault(false, defaultBlock.Range(), defaultBlock.Reference())
	}
	return types.Bool(
		true,
		defaultBlock.Range(),
		defaultBlock.Reference(),
	)
}

func hasLogging(b block.Block) types.BoolValue {
	if loggingBlock := b.GetBlock("logging"); loggingBlock.IsNotNil() {
		if targetAttr := loggingBlock.GetAttribute("target_bucket"); targetAttr.IsNotNil() {
			return types.Bool(true, targetAttr.Range(), targetAttr.Reference())
		}
		return types.BoolDefault(false, loggingBlock.Range(), loggingBlock.Reference())
	}
	return types.BoolDefault(false, b.Range(), b.Reference())
}

func isVersioned(b block.Block) types.BoolValue {
	if versioningBlock := b.GetBlock("versioning"); versioningBlock.IsNotNil() {
		if enabledAttr := versioningBlock.GetAttribute("enabled"); enabledAttr.IsNotNil() {
			return enabledAttr.AsBoolValue(true)
		}
		return types.BoolDefault(
			true,
			versioningBlock.Range(),
			versioningBlock.Reference(),
		)
	}
	return types.BoolDefault(
		false,
		b.Range(),
		b.Reference(),
	)
}
