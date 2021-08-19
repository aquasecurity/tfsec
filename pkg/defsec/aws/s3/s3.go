package s3

import (
	"github.com/aquasecurity/tfsec/pkg/defsec/definition"
	"github.com/aquasecurity/tfsec/pkg/result"
)

type S3 struct {
	Buckets []Bucket
}

type Bucket struct {
	definition.Metadata
	PublicAccessBlock PublicAccessBlock
	BucketPolicy      BucketPolicy
	Encryption        BucketEncryption
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

func (b *Bucket) CheckEncryptionIsEnabled(set result.Set) {

	if !b.Encryption.Enabled.Value {
		set.AddResult().
			WithDescription("Resource '%s' defines an unencrypted S3 bucket.", b.Reference)
	}
}
