package cloudtrail

import "github.com/aquasecurity/defsec/types"

type CloudTrail struct {
	types.Metadata
	Trails []Trail
}

type Trail struct {
	types.Metadata
	Name                    types.StringValue
	EnableLogFileValidation types.BoolValue
	IsMultiRegion           types.BoolValue
	KMSKeyID                types.StringValue
}

func (c *Trail) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Trail) GetRawValue() interface{} {
	return nil
}

func (c *CloudTrail) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *CloudTrail) GetRawValue() interface{} {
	return nil
}
