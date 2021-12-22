package digitalocean

import (
	"github.com/aquasecurity/defsec/provider/digitalocean"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/digitalocean/compute"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/digitalocean/spaces"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) digitalocean.DigitalOcean {
	return digitalocean.DigitalOcean{
		Compute: compute.Adapt(modules),
		Spaces:  spaces.Adapt(modules),
	}
}
