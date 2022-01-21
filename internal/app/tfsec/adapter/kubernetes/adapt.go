package kubernetes

import (
	"github.com/aquasecurity/defsec/provider/kubernetes"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules block.Modules) kubernetes.Kubernetes {
	return kubernetes.Kubernetes{
		NetworkPolicies: adaptNetworkPolicies(modules),
	}
}

func adaptNetworkPolicies(modules block.Modules) []kubernetes.NetworkPolicy {
	var networkPolicies []kubernetes.NetworkPolicy
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("kubernetes_network_policy") {
			networkPolicies = append(networkPolicies, adaptNetworkPolicy(resource))
		}
	}
	return networkPolicies
}

func adaptNetworkPolicy(resourceBlock block.Block) kubernetes.NetworkPolicy {

	var spec kubernetes.Spec

	egressBlock := resourceBlock.GetBlock("spec").GetBlock("egress")
	ingressBlock := resourceBlock.GetBlock("spec").GetBlock("ingress")

	for _, port := range egressBlock.GetBlocks("ports") {
		numberAttr := port.GetAttribute("number")
		numberVal := numberAttr.AsStringValueOrDefault("", port)

		protocolAttr := port.GetAttribute("protocol")
		protocolVal := protocolAttr.AsStringValueOrDefault("", port)

		spec.Egress.Ports = append(spec.Egress.Ports, kubernetes.Port{
			Number:   numberVal,
			Protocol: protocolVal,
		})
	}

	for _, to := range egressBlock.GetBlocks("to") {
		cidrAtrr := to.GetBlock("ip_block").GetAttribute("cidr")
		cidrVal := cidrAtrr.AsStringValueOrDefault("", to)

		spec.Egress.DestinationCIDRs = append(spec.Egress.DestinationCIDRs, cidrVal)
	}

	for _, port := range ingressBlock.GetBlocks("ports") {
		numberAttr := port.GetAttribute("number")
		numberVal := numberAttr.AsStringValueOrDefault("", port)

		protocolAttr := port.GetAttribute("protocol")
		protocolVal := protocolAttr.AsStringValueOrDefault("", port)

		spec.Ingress.Ports = append(spec.Ingress.Ports, kubernetes.Port{
			Number:   numberVal,
			Protocol: protocolVal,
		})
	}

	for _, from := range ingressBlock.GetBlocks("from") {
		cidrAtrr := from.GetBlock("ip_block").GetAttribute("cidr")
		cidrVal := cidrAtrr.AsStringValueOrDefault("", from)

		spec.Ingress.SourceCIDRs = append(spec.Ingress.SourceCIDRs, cidrVal)
	}

	return kubernetes.NetworkPolicy{
		Spec: spec,
	}
}
