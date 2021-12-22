package compute

import (
	"github.com/aquasecurity/defsec/provider/azure/compute"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) compute.Compute {
	return compute.Compute{}
}
