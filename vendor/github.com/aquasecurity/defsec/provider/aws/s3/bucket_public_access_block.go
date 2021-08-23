package s3

import "github.com/aquasecurity/defsec/definition"

type PublicAccessBlock struct {
	*definition.Metadata
	Bucket                *Bucket
	BlockPublicACLs       definition.BoolValue
	BlockPublicPolicy     definition.BoolValue
	IgnorePublicACLs      definition.BoolValue
	RestrictPublicBuckets definition.BoolValue
}
