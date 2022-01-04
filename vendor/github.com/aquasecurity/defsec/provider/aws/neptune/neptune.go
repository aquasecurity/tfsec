package neptune

import "github.com/aquasecurity/defsec/types"

type Neptune struct {
	Clusters []Cluster
}

type Cluster struct {
	types.Metadata
	Logging          Logging
	StorageEncrypted types.BoolValue
	KMSKeyID         types.StringValue
}

type Logging struct {
	Audit types.BoolValue
}

func (c *Cluster) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Cluster) GetRawValue() interface{} {
	return nil
}
