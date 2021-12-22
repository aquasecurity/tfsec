package s3

import "github.com/aquasecurity/defsec/types"

type Bucket struct {
	types.Metadata
	Name              types.StringValue
	PublicAccessBlock *PublicAccessBlock
	BucketPolicy      BucketPolicy
	Encryption        Encryption
	Versioning        Versioning
	Logging           Logging
	ACL               types.StringValue
}

func (b *Bucket) HasPublicExposureACL() bool {
	for _, publicACL := range []string{"public-read", "public-read-write", "website", "authenticated-read"} {
		if b.ACL.EqualTo(publicACL) {
			return true
		}
	}
	return false
}

type BucketPolicy struct {
}

type Logging struct {
	Enabled      types.BoolValue
	TargetBucket types.StringValue
}

type Versioning struct {
	Enabled types.BoolValue
}

type Encryption struct {
	Enabled   types.BoolValue
	Algorithm types.StringValue
	KMSKeyId  types.StringValue
}

func (b *Bucket) GetMetadata() *types.Metadata {
	return &b.Metadata
}

func (b *Bucket) GetRawValue() interface{} {
	return nil
}
