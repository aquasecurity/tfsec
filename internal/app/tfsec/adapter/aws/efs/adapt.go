package efs

import (
	"github.com/aquasecurity/defsec/provider/aws/efs"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) efs.EFS {
	return efs.EFS{}
}
