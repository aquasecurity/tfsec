package compute

import "github.com/aquasecurity/defsec/types"

type Compute struct {
	types.Metadata
	Instances []Instance
}

type Instance struct {
	types.Metadata
	UserData types.StringValue // not b64 encoded pls
}

func (c *Compute) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Compute) GetRawValue() interface{} {
	return nil
}

func (i *Instance) GetMetadata() *types.Metadata {
	return &i.Metadata
}

func (i *Instance) GetRawValue() interface{} {
	return nil
}
