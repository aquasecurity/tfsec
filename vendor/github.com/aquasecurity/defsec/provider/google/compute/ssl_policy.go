package compute

import "github.com/aquasecurity/defsec/types"

type SSLPolicy struct {
	types.Metadata
	Name              types.StringValue
	Profile           types.StringValue
	MinimumTLSVersion types.StringValue
}
