package vpc

import (
	"github.com/aquasecurity/defsec/provider/aws/vpc"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) vpc.VPC {
	return vpc.VPC{}
}
