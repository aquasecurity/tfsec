package autoscaling

import (
	"github.com/aquasecurity/defsec/provider/aws/autoscaling"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) autoscaling.Autoscaling {
	return autoscaling.Autoscaling{}
}
