package s3

import (
	"github.com/aquasecurity/defsec/provider/aws/s3"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func getBuckets(modules block.Modules) []s3.Bucket {
	var buckets []s3.Bucket
	blocks := modules.GetResourcesByType("aws_s3_bucket")
	for _, b := range blocks {
		func(block *block.Block) {
			bucket := s3.Bucket{
				Name:     b.GetAttribute("bucket").AsStringValueOrDefault("", b),
				Metadata: block.Metadata(),
				Versioning: s3.Versioning{
					Enabled: isVersioned(block),
				},
				Encryption: s3.Encryption{
					Enabled: isEncrypted(block),
				},
				Logging: s3.Logging{
					Enabled: hasLogging(block),
				},
				ACL: b.GetAttribute("acl").AsStringValueOrDefault("", b),
			}
			buckets = append(buckets, bucket)
		}(b)
	}

	return buckets
}

func isEncrypted(b *block.Block) types.BoolValue {
	encryptionBlock := b.GetBlock("server_side_encryption_configuration")
	if encryptionBlock.IsNil() {
		return types.BoolDefault(false, b.Metadata())
	}
	ruleBlock := encryptionBlock.GetBlock("rule")
	if ruleBlock.IsNil() {
		return types.BoolDefault(false, encryptionBlock.Metadata())
	}
	defaultBlock := ruleBlock.GetBlock("apply_server_side_encryption_by_default")
	if defaultBlock.IsNil() {
		return types.BoolDefault(false, ruleBlock.Metadata())
	}
	sseAlgorithm := defaultBlock.GetAttribute("sse_algorithm")
	if sseAlgorithm.IsNil() {
		return types.BoolDefault(false, defaultBlock.Metadata())
	}
	return types.Bool(
		true,
		sseAlgorithm.Metadata(),
	)
}

func hasLogging(b *block.Block) types.BoolValue {
	if loggingBlock := b.GetBlock("logging"); loggingBlock.IsNotNil() {
		if targetAttr := loggingBlock.GetAttribute("target_bucket"); targetAttr.IsNotNil() && targetAttr.IsNotEmpty() {
			return types.Bool(true, targetAttr.Metadata())
		}
		return types.BoolDefault(false, loggingBlock.Metadata())
	}
	return types.BoolDefault(false, b.Metadata())
}

func isVersioned(b *block.Block) types.BoolValue {
	if versioningBlock := b.GetBlock("versioning"); versioningBlock.IsNotNil() {
		return versioningBlock.GetAttribute("enabled").AsBoolValueOrDefault(true, versioningBlock)
	}
	return types.BoolDefault(
		false,
		b.Metadata(),
	)
}
