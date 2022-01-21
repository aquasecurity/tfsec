package cloudstack

import (
	"github.com/aquasecurity/defsec/provider/cloudstack"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/cloudstack/compute"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules block.Modules) cloudstack.CloudStack {
	return cloudstack.CloudStack{
		Compute: compute.Adapt(modules),
	}
}
