package digitalocean

import (
	"github.com/aquasecurity/defsec/provider/digitalocean"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/digitalocean/compute"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/digitalocean/spaces"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) digitalocean.DigitalOcean {
	return digitalocean.DigitalOcean{
		Compute: compute.Adapt(modules),
		Spaces:  spaces.Adapt(modules),
	}
}
