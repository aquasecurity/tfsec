package cloudstack

import (
	"github.com/aquasecurity/defsec/provider/cloudstack/compute"
	"github.com/aquasecurity/defsec/types"
)

type CloudStack struct {
	types.Metadata
	Compute compute.Compute
}
