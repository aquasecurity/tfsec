package rds

import "github.com/aquasecurity/defsec/types"

type Classic struct {
	types.Metadata
	DBSecurityGroups []DBSecurityGroup
}

type DBSecurityGroup struct {
	types.Metadata
}

func (g *DBSecurityGroup) GetMetadata() *types.Metadata {
	return &g.Metadata
}

func (g *DBSecurityGroup) GetRawValue() interface{} {
	return nil
}


func (c *Classic) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Classic) GetRawValue() interface{} {
	return nil
}    
