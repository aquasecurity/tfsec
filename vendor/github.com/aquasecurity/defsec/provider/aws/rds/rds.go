package rds

import "github.com/aquasecurity/defsec/types"

type RDS struct {
	Instances []Instance
	Clusters  []Cluster
	Classic   Classic
}

type Cluster struct {
	types.Metadata
	BackupRetentionPeriodDays types.IntValue
	ReplicationSourceARN      types.StringValue
	PerformanceInsights       PerformanceInsights
	Instances                 []ClusterInstance
	Encryption                Encryption
}

type Encryption struct {
	EncryptStorage types.BoolValue
	KMSKeyID       types.StringValue
}

type Instance struct {
	types.Metadata
	BackupRetentionPeriodDays types.IntValue
	ReplicationSourceARN      types.StringValue
	PerformanceInsights       PerformanceInsights
	Encryption                Encryption
	PublicAccess              types.BoolValue
}

type ClusterInstance Instance

type PerformanceInsights struct {
	Enabled  types.BoolValue
	KMSKeyID types.StringValue
}

func (c *Cluster) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Cluster) GetRawValue() interface{} {
	return nil
}

func (i *Instance) GetMetadata() *types.Metadata {
	return &i.Metadata
}

func (i *Instance) GetRawValue() interface{} {
	return nil
}

func (i *ClusterInstance) GetMetadata() *types.Metadata {
	return &i.Metadata
}

func (i *ClusterInstance) GetRawValue() interface{} {
	return nil
}
