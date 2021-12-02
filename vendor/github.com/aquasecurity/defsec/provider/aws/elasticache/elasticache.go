package elasticache

import "github.com/aquasecurity/defsec/types"

type ElastiCache struct {
	Clusters          []Cluster
	ReplicationGroups []ReplicationGroup
	SecurityGroups    []SecurityGroup
}

type Cluster struct {
	types.Metadata
	Engine                 types.StringValue
	NodeType               types.StringValue
	SnapshotRetentionLimit types.IntValue // days
}

type ReplicationGroup struct {
	types.Metadata
	TransitEncryptionEnabled types.BoolValue
}

type SecurityGroup struct {
	types.Metadata
	Description types.StringValue
}

func (c *SecurityGroup) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *SecurityGroup) GetRawValue() interface{} {
	return nil
}

func (c *Cluster) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Cluster) GetRawValue() interface{} {
	return nil
}

func (r *ReplicationGroup) GetMetadata() *types.Metadata {
	return &r.Metadata
}

func (r *ReplicationGroup) GetRawValue() interface{} {
	return nil
}
