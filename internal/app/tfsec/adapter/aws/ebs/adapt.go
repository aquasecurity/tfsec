package ebs

import (
	"github.com/aquasecurity/defsec/provider/aws/ebs"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) ebs.EBS {
	return ebs.EBS{}
}
