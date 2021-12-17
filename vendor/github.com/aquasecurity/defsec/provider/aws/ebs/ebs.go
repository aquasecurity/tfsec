package ebs

import "github.com/aquasecurity/defsec/types"

type EBS struct {
	Volumes []Volume
}

type Volume struct {
	types.Metadata
	Encryption Encryption
}

type Encryption struct {
	Enabled  types.BoolValue
	KMSKeyID types.StringValue
}

func (c *Volume) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Volume) GetRawValue() interface{} {
	return nil
}
