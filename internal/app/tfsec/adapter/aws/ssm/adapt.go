package ssm

import (
	"github.com/aquasecurity/defsec/provider/aws/ssm"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) ssm.SSM {
	return ssm.SSM{}
}
