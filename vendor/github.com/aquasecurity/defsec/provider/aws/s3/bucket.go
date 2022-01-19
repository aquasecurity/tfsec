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
	types.Metadata
}

type Logging struct {
	types.Metadata
	Enabled      types.BoolValue
	TargetBucket types.StringValue
}

type Versioning struct {
	types.Metadata
	Enabled types.BoolValue
}

type Encryption struct {
	types.Metadata
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

func (b *BucketPolicy) GetMetadata() *types.Metadata {
	return &b.Metadata
}

func (b *BucketPolicy) GetRawValue() interface{} {
	return nil
}

func (l *Logging) GetMetadata() *types.Metadata {
	return &l.Metadata
}

func (l *Logging) GetRawValue() interface{} {
	return nil
}

func (v *Versioning) GetMetadata() *types.Metadata {
	return &v.Metadata
}

func (v *Versioning) GetRawValue() interface{} {
	return nil
}

func (e *Encryption) GetMetadata() *types.Metadata {
	return &e.Metadata
}

func (e *Encryption) GetRawValue() interface{} {
	return nil
}
