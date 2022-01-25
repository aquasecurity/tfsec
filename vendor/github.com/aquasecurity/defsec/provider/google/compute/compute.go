package compute

import "github.com/aquasecurity/defsec/types"

type Compute struct {
	types.Metadata
	Disks           []Disk
	Networks        []Network
	SSLPolicies     []SSLPolicy
	ProjectMetadata ProjectMetadata
	Instances       []Instance
}

func (c *Compute) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Compute) GetRawValue() interface{} {
	return nil
}
