package s3

import (
	"strings"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/pkg/defsec/aws/s3"
	"github.com/aquasecurity/tfsec/pkg/defsec/definition"
)

func Adapt(modules []block.Module) s3.S3 {
	buckets := getBuckets(modules)
	publicAccessBlocks := getPublicAccessBlocks(modules, buckets)

	return s3.S3{
		Buckets:            buckets,
		PublicAccessBlocks: publicAccessBlocks,
	}
}

func getBuckets(modules block.Modules) []s3.Bucket {
	var buckets []s3.Bucket
	blocks := modules.GetBlocksByTypeLabel("aws_s3_bucket")
	for _, b := range blocks {
		func(block block.Block) {
			s3b := s3.Bucket{
				Name:     getName(block),
				Metadata: definition.NewMetadata(block.Range()).WithReference(block.Reference()),
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

func getPublicAccessBlocks(modules block.Modules, buckets []s3.Bucket) []s3.PublicAccessBlock {
	var publicAccessBlocks []s3.PublicAccessBlock

	for _, module := range modules {
		blocks := module.GetBlocksByTypeLabel("aws_s3_bucket_public_access_block")
		for _, b := range blocks {

			pba := s3.PublicAccessBlock{
				Metadata: definition.NewMetadata(b.Range()).WithReference(b.Reference()),
			}

			var bucketName string

			bucketAttr := b.GetAttribute("bucket")

			if bucketAttr.IsString() {
				bucketName = bucketAttr.Value().AsString()
			}

			references := bucketAttr.AllReferences(b)

			for i, bucket := range buckets {
				if bucketName != "" && bucket.Name.Value == bucketName && buckets[i].PublicAccessBlock == nil {
					pba.Bucket = &bucket
					buckets[i].PublicAccessBlock = &pba
					break
				}
				for _, ref := range references {
					if ref.RefersTo(bucket.Reference) || (strings.HasPrefix(bucket.Reference.String(), ref.String()) && buckets[i].PublicAccessBlock == nil) {
						pba.Bucket = &bucket
						buckets[i].PublicAccessBlock = &pba
						break
					}
				}
			}

			publicAccessBlocks = append(publicAccessBlocks, pba)
		}
	}

	return publicAccessBlocks
}

func getName(b block.Block) definition.StringValue {
	if nameAttr := b.GetAttribute("bucket"); nameAttr.IsString() {
		return definition.StringValue{
			Metadata: definition.NewMetadata(nameAttr.Range()),
			Value:    nameAttr.Value().AsString(),
		}
	}
	return definition.StringValue{
		Metadata: definition.NewMetadata(b.Range()),
		Value:    "",
	}

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
