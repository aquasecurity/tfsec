package ecr

import (
	"github.com/aquasecurity/defsec/provider/aws/ecr"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) ecr.ECR {
	return ecr.ECR{}
}
