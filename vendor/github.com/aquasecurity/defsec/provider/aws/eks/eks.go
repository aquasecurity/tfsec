package eks

import "github.com/aquasecurity/defsec/types"

type EKS struct {
	types.Metadata
	Clusters []Cluster
}

type Cluster struct {
	types.Metadata
	Logging             Logging
	Encryption          Encryption
	PublicAccessEnabled types.BoolValue
	PublicAccessCIDRs   []types.StringValue
}

type Logging struct {
	types.Metadata
	API               types.BoolValue
	Audit             types.BoolValue
	Authenticator     types.BoolValue
	ControllerManager types.BoolValue
	Scheduler         types.BoolValue
}

type Encryption struct {
	types.Metadata
	Secrets  types.BoolValue
	KMSKeyID types.StringValue
}

func (c *Cluster) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Cluster) GetRawValue() interface{} {
	return nil
}

func (e *EKS) GetMetadata() *types.Metadata {
	return &e.Metadata
}

func (e *EKS) GetRawValue() interface{} {
	return nil
}

func (l *Logging) GetMetadata() *types.Metadata {
	return &l.Metadata
}

func (l *Logging) GetRawValue() interface{} {
	return nil
}

func (e *Encryption) GetMetadata() *types.Metadata {
	return &e.Metadata
}

func (e *Encryption) GetRawValue() interface{} {
	return nil
}
