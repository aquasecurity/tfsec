package compute

import (
	"github.com/aquasecurity/defsec/provider/google/compute"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func adaptInstances(modules block.Modules) (instances []compute.Instance) {

	for _, instanceBlock := range modules.GetResourcesByType("google_compute_instance") {
		var instance compute.Instance
		for _, networkInterfaceBlock := range instanceBlock.GetBlocks("network_interface") {
			var ni compute.NetworkInterface
			ni.HasPublicIP = types.BoolDefault(false, networkInterfaceBlock.Metadata())
			if accessConfigBlock := networkInterfaceBlock.GetBlock("access_config"); accessConfigBlock.IsNotNil() {
				ni.HasPublicIP = types.Bool(true, accessConfigBlock.Metadata())
			}
			instance.NetworkInterfaces = append(instance.NetworkInterfaces, ni)
		}
		instances = append(instances, instance)
	}

	return instances
}
