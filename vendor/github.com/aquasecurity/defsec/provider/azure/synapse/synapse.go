package synapse

import "github.com/aquasecurity/defsec/types"

type Synapse struct {
	types.Metadata
	Workspaces []Workspace
}

type Workspace struct {
	types.Metadata
	EnableManagedVirtualNetwork types.BoolValue
}


func (s *Synapse) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s *Synapse) GetRawValue() interface{} {
	return nil
}    


func (w *Workspace) GetMetadata() *types.Metadata {
	return &w.Metadata
}

func (w *Workspace) GetRawValue() interface{} {
	return nil
}    
