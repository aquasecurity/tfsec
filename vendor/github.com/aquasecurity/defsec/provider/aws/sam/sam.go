package sam

import "github.com/aquasecurity/defsec/types"

type SAM struct {
	types.Metadata
	APIs          []API
	Applications  []Application
	Functions     []Function
	HttpAPIs      []HttpAPI
	SimpleTables  []SimpleTable
	StateMachines []StateMachine
}

func (s *SAM) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s *SAM) GetRawValue() interface{} {
	return nil
}
