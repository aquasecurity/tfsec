package google

import (
	"github.com/aquasecurity/defsec/provider/google"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/google/compute"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules block.Modules) google.Google {
	return google.Google{
		Compute: compute.Adapt(modules),
	}
}
