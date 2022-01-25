package ec2

import "github.com/aquasecurity/defsec/types"

type EC2 struct {
	types.Metadata
	Instances []Instance
}

func (e *EC2) GetMetadata() *types.Metadata {
	return &e.Metadata
}

func (e *EC2) GetRawValue() interface{} {
	return nil
}
