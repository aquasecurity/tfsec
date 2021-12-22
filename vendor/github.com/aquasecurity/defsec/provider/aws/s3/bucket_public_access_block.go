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
