package s3

import "github.com/aquasecurity/defsec/types"

type S3 struct {
	types.Metadata
	Buckets []Bucket
}

func (s *S3) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s *S3) GetRawValue() interface{} {
	return nil
}
