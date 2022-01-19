package digitalocean

import (
	"github.com/aquasecurity/defsec/provider/digitalocean/compute"
	"github.com/aquasecurity/defsec/provider/digitalocean/spaces"
	"github.com/aquasecurity/defsec/types"
)

type DigitalOcean struct {
	types.Metadata
	Compute compute.Compute
	Spaces  spaces.Spaces
}
