package compute

import "github.com/aquasecurity/defsec/types"

type SubNetwork struct {
	types.Metadata
	Name           types.StringValue
	EnableFlowLogs types.BoolValue
}


func (s *SubNetwork) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s *SubNetwork) GetRawValue() interface{} {
	return nil
}    
