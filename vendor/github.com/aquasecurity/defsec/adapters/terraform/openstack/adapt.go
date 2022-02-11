package openstack

import (
	"github.com/aquasecurity/defsec/provider/openstack"
	"github.com/aquasecurity/trivy-config-parsers/terraform"
)

func Adapt(modules terraform.Modules) openstack.OpenStack {
	return openstack.OpenStack{
		Compute: adaptCompute(modules),
	}
}

func adaptCompute(modules terraform.Modules) openstack.Compute {
	var compute openstack.Compute

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("openstack_compute_instance_v2") {
			compute.Instances = append(compute.Instances, adaptInstance(resource))
		}
	}
	compute.Firewall = adaptFirewall(modules)

	return compute
}

func adaptInstance(resourceBlock *terraform.Block) openstack.Instance {
	adminPassAttr := resourceBlock.GetAttribute("admin_pass")
	adminPassVal := adminPassAttr.AsStringValueOrDefault("", resourceBlock)

	return openstack.Instance{
		Metadata:      resourceBlock.GetMetadata(),
		AdminPassword: adminPassVal,
	}
}

func adaptFirewall(modules terraform.Modules) openstack.Firewall {
	var firewall openstack.Firewall

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("openstack_fw_rule_v1") {

			sourceAttr := resource.GetAttribute("source_ip_address")
			sourceVal := sourceAttr.AsStringValueOrDefault("", resource)

			destinationAttr := resource.GetAttribute("destination_ip_address")
			destinationVal := destinationAttr.AsStringValueOrDefault("", resource)

			sourcePortAttr := resource.GetAttribute("source_port")
			sourcePortVal := sourcePortAttr.AsStringValueOrDefault("", resource)

			destinationPortAttr := resource.GetAttribute("destination_port")
			destinationPortVal := destinationPortAttr.AsStringValueOrDefault("", resource)

			enabledAttr := resource.GetAttribute("enabled")
			enabledVal := enabledAttr.AsBoolValueOrDefault(true, resource)

			if resource.GetAttribute("action").Equals("allow") {
				firewall.AllowRules = append(firewall.AllowRules, openstack.Rule{
					Metadata:        resource.GetMetadata(),
					Source:          sourceVal,
					Destination:     destinationVal,
					SourcePort:      sourcePortVal,
					DestinationPort: destinationPortVal,
					Enabled:         enabledVal,
				})
			} else if resource.GetAttribute("action").Equals("deny") {
				firewall.DenyRules = append(firewall.DenyRules, openstack.Rule{
					Metadata:        resource.GetMetadata(),
					Source:          sourceVal,
					Destination:     destinationVal,
					SourcePort:      sourcePortVal,
					DestinationPort: destinationPortVal,
					Enabled:         enabledVal,
				})
			}
		}
	}
	return firewall
}
