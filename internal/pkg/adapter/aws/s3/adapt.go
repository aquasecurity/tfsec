package s3

import (
	"github.com/aquasecurity/defsec/provider/aws/s3"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) s3.S3 {

	a := &adapter{
		modules:   modules,
		bucketMap: make(map[string]s3.Bucket),
	}

	return s3.S3{
		Buckets: a.adaptBuckets(),
	}
}
