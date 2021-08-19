package s3

import (
	"github.com/aquasecurity/tfsec/pkg/defsec/definition"
)

type S3 struct {
	Buckets []Bucket
}

type Bucket struct {
	*definition.Metadata
	PublicAccessBlock PublicAccessBlock
	BucketPolicy      BucketPolicy
	Encryption        BucketEncryption
	Versioning        Versioning
}

type PublicAccessBlock struct {
}

type BucketPolicy struct {
}

type Versioning struct {
	Enabled definition.BoolValue
}

type BucketEncryption struct {
	Enabled   definition.BoolValue
	Algorithm definition.StringValue
	KMSKeyId  definition.StringValue
}
