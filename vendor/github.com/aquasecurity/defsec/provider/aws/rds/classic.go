package rds

import "github.com/aquasecurity/trivy-config-parsers/types"

type Classic struct {
	types.Metadata
	DBSecurityGroups []DBSecurityGroup
}

type DBSecurityGroup struct {
	types.Metadata
}
