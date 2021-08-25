package s3

import (
	"strings"

	"github.com/aquasecurity/defsec/provider/aws/s3"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func getPublicAccessBlocks(modules block.Modules, buckets []s3.Bucket) []s3.PublicAccessBlock {
	var publicAccessBlocks []s3.PublicAccessBlock

	for _, module := range modules {
		blocks := module.GetBlocksByTypeLabel("aws_s3_bucket_public_access_block")
		for _, b := range blocks {

			pba := s3.PublicAccessBlock{
				Metadata:              types.NewMetadata(b.Range()).WithReference(b.Reference()),
				BlockPublicACLs:       isAttrTrue(b, "block_public_acls"),
				BlockPublicPolicy:     isAttrTrue(b, "block_public_policy"),
				IgnorePublicACLs:      isAttrTrue(b, "ignore_public_acls"),
				RestrictPublicBuckets: isAttrTrue(b, "restrict_public_buckets"),
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

func isAttrTrue(block block.Block, attrName string) types.BoolValue {
	attr := block.GetAttribute(attrName)
	if attr.IsNil() {
		return types.BoolValue{
			Value:    false,
			Metadata: types.NewMetadata(block.Range()),
		}
	}
	return types.BoolValue{
		Value:    attr.IsTrue(),
		Metadata: types.NewMetadata(attr.Range()),
	}
}
