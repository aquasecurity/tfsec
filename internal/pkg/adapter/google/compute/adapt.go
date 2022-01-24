package compute

import (
	"github.com/aquasecurity/defsec/provider/google/compute"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) compute.Compute {
	return compute.Compute{
		ProjectMetadata: adaptProjectMetadata(modules),
		Instances:       adaptInstances(modules),
		Disks:           adaptDisks(modules),
		Networks:        adaptNetworks(modules),
		SSLPolicies:     adaptSSLPolicies(modules),
	}
}
