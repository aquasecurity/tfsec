package s3

import (
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapters"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/pkg/defsec/aws/s3"
	"github.com/aquasecurity/tfsec/pkg/defsec/definition"
)

func Adapt(modules []block.Module) s3.S3 {
	return s3.S3{
		Buckets: getBuckets(modules),
	}
}

func getBuckets(modules []block.Module) []s3.Bucket {
	var buckets []s3.Bucket
	blocks := adapters.GetBlocksByTypeLabel("aws_s3_bucket", modules...)
	for _, block := range blocks {
		buckets = append(buckets, s3.Bucket{
			Metadata: definition.NewMetadata(block.Range()),
		})
	}
	return buckets

}
