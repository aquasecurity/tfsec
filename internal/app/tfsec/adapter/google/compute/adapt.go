package compute

import (
	"github.com/aquasecurity/defsec/provider/google/compute"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules block.Modules) compute.Compute {
	return compute.Compute{
		Instances: getInstances(modules),
	}
}
