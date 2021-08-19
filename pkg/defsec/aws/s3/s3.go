package s3

import "github.com/aquasecurity/tfsec/pkg/defsec/definition"

type Bucket struct {
	definition.Metadata
	PublicAccessBlock PublicAccessBlock
	BucketPolicy      BucketPolicy
	BucketEncryption  BucketEncryption
}

type PublicAccessBlock struct {
	definition.Metadata
}

type BucketPolicy struct {
	definition.Metadata
}

type BucketEncryption struct {
	definition.Metadata
	Enabled   definition.BoolValue
	Algorithm definition.StringValue
	KMSKeyId  definition.StringValue
}
