package dynamodb

import "github.com/aquasecurity/defsec/types"

type DynamoDB struct {
	DAXClusters []DAXCluster
}

type DAXCluster struct {
	types.Metadata
	ServerSideEncryption ServerSideEncryption
	PointInTimeRecovery  types.BoolValue
}

type ServerSideEncryption struct {
	Enabled  types.BoolValue
	KMSKeyID types.StringValue
}

func (c *DAXCluster) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *DAXCluster) GetRawValue() interface{} {
	return nil
}
