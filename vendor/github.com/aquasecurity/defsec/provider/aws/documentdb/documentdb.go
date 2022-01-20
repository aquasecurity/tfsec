package documentdb

import "github.com/aquasecurity/defsec/types"

type DocumentDB struct {
	types.Metadata
	Clusters []Cluster
}

const (
	LogExportAudit    = "audit"
	LogExportProfiler = "profiler"
)

type Cluster struct {
	types.Metadata
	Identifier        types.StringValue
	EnabledLogExports []types.StringValue
	Instances         []Instance
	StorageEncrypted  types.BoolValue
	KMSKeyID          types.StringValue
}

type Instance struct {
	types.Metadata
	KMSKeyID types.StringValue
}

func (i *Instance) GetMetadata() *types.Metadata {
	return &i.Metadata
}

func (i *Instance) GetRawValue() interface{} {
	return nil
}

func (d *DocumentDB) GetMetadata() *types.Metadata {
	return &d.Metadata
}

func (d *DocumentDB) GetRawValue() interface{} {
	return nil
}

func (c *Cluster) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Cluster) GetRawValue() interface{} {
	return nil
}
