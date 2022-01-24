package cloudstack

import (
	"github.com/aquasecurity/defsec/provider/cloudstack"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/cloudstack/compute"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) cloudstack.CloudStack {
	return cloudstack.CloudStack{
		Compute: compute.Adapt(modules),
	}
}
