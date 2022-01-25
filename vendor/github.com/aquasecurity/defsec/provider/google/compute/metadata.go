package compute

import "github.com/aquasecurity/defsec/types"

type ProjectMetadata struct {
	types.Metadata
	EnableOSLogin types.BoolValue
}


func (p *ProjectMetadata) GetMetadata() *types.Metadata {
	return &p.Metadata
}

func (p *ProjectMetadata) GetRawValue() interface{} {
	return nil
}    
