package rds

import (
	"github.com/aquasecurity/defsec/provider/aws/rds"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) rds.RDS {
	return rds.RDS{}
}
