package openstack

import (
	"github.com/aquasecurity/defsec/provider/openstack"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) openstack.OpenStack {
	return openstack.OpenStack{
		Compute: openstack.Compute{},
	}
}
