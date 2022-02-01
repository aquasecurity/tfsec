package kubernetes

import (
	"github.com/aquasecurity/defsec/provider/kubernetes"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
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

func adaptNetworkPolicy(resourceBlock *block.Block) kubernetes.NetworkPolicy {

	policy := kubernetes.NetworkPolicy{
		Metadata: resourceBlock.Metadata(),
		Spec: kubernetes.Spec{
			Metadata: resourceBlock.Metadata(),
			Egress: kubernetes.Egress{
				Metadata: resourceBlock.Metadata(),
			},
			Ingress: kubernetes.Ingress{
				Metadata: resourceBlock.Metadata(),
			},
		},
	}

	if specBlock := resourceBlock.GetBlock("spec"); specBlock.IsNotNil() {
		if egressBlock := specBlock.GetBlock("egress"); egressBlock.IsNotNil() {
			policy.Spec.Egress.Metadata = egressBlock.Metadata()
			for _, port := range egressBlock.GetBlocks("ports") {
				numberAttr := port.GetAttribute("number")
				numberVal := numberAttr.AsStringValueOrDefault("", port)

				protocolAttr := port.GetAttribute("protocol")
				protocolVal := protocolAttr.AsStringValueOrDefault("", port)

				policy.Spec.Egress.Ports = append(policy.Spec.Egress.Ports, kubernetes.Port{
					Metadata: port.Metadata(),
					Number:   numberVal,
					Protocol: protocolVal,
				})
			}

			for _, to := range egressBlock.GetBlocks("to") {
				cidrAtrr := to.GetBlock("ip_block").GetAttribute("cidr")
				cidrVal := cidrAtrr.AsStringValueOrDefault("", to)

				policy.Spec.Egress.DestinationCIDRs = append(policy.Spec.Egress.DestinationCIDRs, cidrVal)
			}
		}

		if ingressBlock := specBlock.GetBlock("ingress"); ingressBlock.IsNotNil() {
			policy.Spec.Ingress.Metadata = ingressBlock.Metadata()
			for _, port := range ingressBlock.GetBlocks("ports") {
				numberAttr := port.GetAttribute("number")
				numberVal := numberAttr.AsStringValueOrDefault("", port)

				protocolAttr := port.GetAttribute("protocol")
				protocolVal := protocolAttr.AsStringValueOrDefault("", port)

				policy.Spec.Ingress.Ports = append(policy.Spec.Ingress.Ports, kubernetes.Port{
					Metadata: port.Metadata(),
					Number:   numberVal,
					Protocol: protocolVal,
				})
			}

			for _, from := range ingressBlock.GetBlocks("from") {
				cidrAtrr := from.GetBlock("ip_block").GetAttribute("cidr")
				cidrVal := cidrAtrr.AsStringValueOrDefault("", from)

				policy.Spec.Ingress.SourceCIDRs = append(policy.Spec.Ingress.SourceCIDRs, cidrVal)
			}
		}
	}

	return policy
}
