package dynamodb

import "github.com/aquasecurity/defsec/types"

type DynamoDB struct {
	types.Metadata
	DAXClusters []DAXCluster
}

type DAXCluster struct {
	types.Metadata
	ServerSideEncryption ServerSideEncryption
	PointInTimeRecovery  types.BoolValue
}

type ServerSideEncryption struct {
	types.Metadata
	Enabled  types.BoolValue
	KMSKeyID types.StringValue
}

const DefaultKMSKeyID = "alias/aws/dynamodb"

func (c *DAXCluster) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *DAXCluster) GetRawValue() interface{} {
	return nil
}

func (d *DynamoDB) GetMetadata() *types.Metadata {
	return &d.Metadata
}

func (d *DynamoDB) GetRawValue() interface{} {
	return nil
}

func (s *ServerSideEncryption) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s *ServerSideEncryption) GetRawValue() interface{} {
	return nil
}
