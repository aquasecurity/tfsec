package elb

import (
	"github.com/aquasecurity/defsec/provider/aws/elb"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) elb.ELB {
	return elb.ELB{}
}
