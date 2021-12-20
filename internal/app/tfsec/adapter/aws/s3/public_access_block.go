package s3

import (
	"strings"

	"github.com/aquasecurity/defsec/provider/aws/s3"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func getPublicAccessBlocks(modules block.Modules, buckets []s3.Bucket) []s3.PublicAccessBlock {
	var publicAccessBlocks []s3.PublicAccessBlock

	for _, module := range modules {
		blocks := module.GetResourcesByType("aws_s3_bucket_public_access_block")
		for _, b := range blocks {

			pba := s3.PublicAccessBlock{
				Metadata:              b.Metadata(),
				BlockPublicACLs:       b.GetAttribute("block_public_acls").AsBoolValueOrDefault(false, b),
				BlockPublicPolicy:     b.GetAttribute("block_public_policy").AsBoolValueOrDefault(false, b),
				IgnorePublicACLs:      b.GetAttribute("ignore_public_acls").AsBoolValueOrDefault(false, b),
				RestrictPublicBuckets: b.GetAttribute("restrict_public_buckets").AsBoolValueOrDefault(false, b),
			}

			var bucketName string
			bucketAttr := b.GetAttribute("bucket")

			if bucketAttr.IsString() {
				bucketName = bucketAttr.Value().AsString()
			}

			references := bucketAttr.AllReferences(b)

			for i, bucket := range buckets {
				if bucketName != "" && bucket.Name.EqualTo(bucketName) && buckets[i].PublicAccessBlock == nil {
					pba.Bucket = &bucket
					buckets[i].PublicAccessBlock = &pba
					break
				}
				for _, ref := range references {
					if ref.RefersTo(bucket.Reference()) || (strings.HasPrefix(bucket.Reference().String(), ref.String()) && buckets[i].PublicAccessBlock == nil) {
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
