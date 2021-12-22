package eks

import (
	"github.com/aquasecurity/defsec/provider/aws/eks"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) eks.EKS {
	return eks.EKS{}
}
