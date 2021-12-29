package compute

import (
	"github.com/aquasecurity/defsec/provider/digitalocean/compute"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) compute.Compute {
	return compute.Compute{
		Droplets: adaptDroplets(modules),
	}
}

func adaptDroplets(module block.Modules) []compute.Droplet {
	var droplets []compute.Droplet

	for _, module := range module {
		for _, block := range module.GetResourcesByType("digitalocean_droplet") {
			droplet := compute.Droplet{
				Metadata: *(block.GetMetadata()),
			}
			sshKeys := block.GetAttribute("ssh_keys")
			if sshKeys != nil {
				droplet.SSHKeys = []types.StringValue{}
				for _, value := range sshKeys.ValueAsStrings() {
					droplet.SSHKeys = append(droplet.SSHKeys, types.String(value, sshKeys.Metadata()))
				}
			}

			droplets = append(droplets, droplet)
		}
	}
	return droplets
}
