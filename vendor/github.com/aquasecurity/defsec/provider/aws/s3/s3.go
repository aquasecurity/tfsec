package s3

import "github.com/aquasecurity/trivy-config-parsers/types"

type S3 struct {
	types.Metadata
	Buckets []Bucket
}
