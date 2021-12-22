package rds

import "github.com/aquasecurity/defsec/types"

type Classic struct {
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
