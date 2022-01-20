package redshift

import "github.com/aquasecurity/defsec/types"

type Redshift struct {
	types.Metadata
	Clusters       []Cluster
	SecurityGroups []SecurityGroup
}

type SecurityGroup struct {
	types.Metadata
	Description types.StringValue
}

type Cluster struct {
	types.Metadata
	Encryption      Encryption
	SubnetGroupName types.StringValue
}

type Encryption struct {
	types.Metadata
	Enabled  types.BoolValue
	KMSKeyID types.StringValue
}

func (g *SecurityGroup) GetMetadata() *types.Metadata {
	return &g.Metadata
}

func (g *SecurityGroup) GetRawValue() interface{} {
	return nil
}

func (c *Cluster) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Cluster) GetRawValue() interface{} {
	return nil
}


func (r *Redshift) GetMetadata() *types.Metadata {
	return &r.Metadata
}

func (r *Redshift) GetRawValue() interface{} {
	return nil
}    


func (e *Encryption) GetMetadata() *types.Metadata {
	return &e.Metadata
}

func (e *Encryption) GetRawValue() interface{} {
	return nil
}    
