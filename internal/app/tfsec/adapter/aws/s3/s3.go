package s3

import (
	"github.com/aquasecurity/defsec/provider/aws/s3"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) s3.S3 {
	buckets := getBuckets(modules)
	publicAccessBlocks := getPublicAccessBlocks(modules, buckets)

	return s3.S3{
		Buckets:            buckets,
		PublicAccessBlocks: publicAccessBlocks,
	}
}
