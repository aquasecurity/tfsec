package cloudstack

import (
	"github.com/aquasecurity/defsec/provider/cloudstack/compute"
	"github.com/aquasecurity/trivy-config-parsers/types"
)

type CloudStack struct {
	types.Metadata
	Compute compute.Compute
}
