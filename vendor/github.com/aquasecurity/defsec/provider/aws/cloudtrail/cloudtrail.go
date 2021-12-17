package cloudtrail

import "github.com/aquasecurity/defsec/types"

type CloudTrail struct {
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
