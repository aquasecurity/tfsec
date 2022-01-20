package s3

import "github.com/aquasecurity/defsec/types"

type PublicAccessBlock struct {
	types.Metadata
	Bucket                *Bucket
	BlockPublicACLs       types.BoolValue
	BlockPublicPolicy     types.BoolValue
	IgnorePublicACLs      types.BoolValue
	RestrictPublicBuckets types.BoolValue
}


func (p *PublicAccessBlock) GetMetadata() *types.Metadata {
	return &p.Metadata
}

func (p *PublicAccessBlock) GetRawValue() interface{} {
	return nil
}    
