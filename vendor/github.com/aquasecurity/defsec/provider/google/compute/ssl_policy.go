package compute

import "github.com/aquasecurity/defsec/types"

type SSLPolicy struct {
	types.Metadata
	Name              types.StringValue
	Profile           types.StringValue
	MinimumTLSVersion types.StringValue
}

func (s *SSLPolicy) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s *SSLPolicy) GetRawValue() interface{} {
	return nil
}
