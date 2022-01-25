package rds

import "github.com/aquasecurity/defsec/types"

type RDS struct {
	types.Metadata
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
	types.Metadata
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

type ClusterInstance struct {
	types.Metadata
	Instance
	ClusterIdentifier types.StringValue
}

type PerformanceInsights struct {
	types.Metadata
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

func (r *RDS) GetMetadata() *types.Metadata {
	return &r.Metadata
}

func (r *RDS) GetRawValue() interface{} {
	return nil
}

func (e *Encryption) GetMetadata() *types.Metadata {
	return &e.Metadata
}

func (e *Encryption) GetRawValue() interface{} {
	return nil
}

func (p *PerformanceInsights) GetMetadata() *types.Metadata {
	return &p.Metadata
}

func (p *PerformanceInsights) GetRawValue() interface{} {
	return nil
}
