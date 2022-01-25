package cloudwatch

import "github.com/aquasecurity/defsec/types"

type CloudWatch struct {
	types.Metadata
	LogGroups []LogGroup
}

type LogGroup struct {
	types.Metadata
	Name            types.StringValue
	KMSKeyID        types.StringValue
	RetentionInDays types.IntValue
}

func (c *LogGroup) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *LogGroup) GetRawValue() interface{} {
	return nil
}

func (c *CloudWatch) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *CloudWatch) GetRawValue() interface{} {
	return nil
}
