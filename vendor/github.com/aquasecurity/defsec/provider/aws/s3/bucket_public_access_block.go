package s3

import "github.com/aquasecurity/trivy-config-parsers/types"

type PublicAccessBlock struct {
	types.Metadata
	BlockPublicACLs       types.BoolValue
	BlockPublicPolicy     types.BoolValue
	IgnorePublicACLs      types.BoolValue
	RestrictPublicBuckets types.BoolValue
}
