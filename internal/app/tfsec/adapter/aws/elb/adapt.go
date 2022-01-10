package elb

import (
	"github.com/aquasecurity/defsec/provider/aws/elb"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) elb.ELB {
	return elb.ELB{
		LoadBalancers: adaptLoadBalancers(modules),
	}
}

func adaptLoadBalancers(modules []block.Module) []elb.LoadBalancer {
	var loadBalancers []elb.LoadBalancer
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_lb") {
			loadBalancers = append(loadBalancers, adaptLoadBalancer(resource, module))
		}
		for _, resource := range module.GetResourcesByType("aws_alb") {
			loadBalancers = append(loadBalancers, adaptLoadBalancer(resource, module))
		}
	}
	return loadBalancers
}

func adaptLoadBalancer(resource block.Block, module block.Module) elb.LoadBalancer {
	var listeners []elb.Listener

	typeAttr := resource.GetAttribute("load_balancer_type")
	typeVal := typeAttr.AsStringValueOrDefault("application", resource)

	dropInvalidHeadersAttr := resource.GetAttribute("drop_invalid_header_fields")
	dropInvalidHeadersVal := dropInvalidHeadersAttr.AsBoolValueOrDefault(false, resource)

	internalAttr := resource.GetAttribute("internal")
	internalVal := internalAttr.AsBoolValueOrDefault(false, resource)

	listenerBlocks := module.GetReferencingResources(resource, "aws_lb_listener", "load_balancer_arn")
	listenerBlocks = append(listenerBlocks, module.GetReferencingResources(resource, "aws_alb_listener", "load_balancer_arn")...)

	for _, listenerBlock := range listenerBlocks {
		protocolAttr := listenerBlock.GetAttribute("protocol")
		protocolVal := protocolAttr.AsStringValueOrDefault("", listenerBlock)
		if typeVal.EqualTo("application") {
			protocolVal = protocolAttr.AsStringValueOrDefault("HTTP", listenerBlock)
		}

		sslPolicyAttr := listenerBlock.GetAttribute("ssl_policy")
		sslPolicyVal := sslPolicyAttr.AsStringValueOrDefault("", listenerBlock)

		actionTypeVal := types.String("", *listenerBlock.GetMetadata())
		if listenerBlock.HasChild("default_action") {
			defaultActionBlock := listenerBlock.GetBlock("default_action")
			actionTypeAttr := defaultActionBlock.GetAttribute("type")
			actionTypeVal = actionTypeAttr.AsStringValueOrDefault("", defaultActionBlock)
		}

		listeners = append(listeners, elb.Listener{
			Metadata:  *listenerBlock.GetMetadata(),
			Protocol:  protocolVal,
			TLSPolicy: sslPolicyVal,
			DefaultAction: elb.Action{
				Type: actionTypeVal,
			},
		})
	}
	return elb.LoadBalancer{
		Metadata:                *resource.GetMetadata(),
		Type:                    typeVal,
		DropInvalidHeaderFields: dropInvalidHeadersVal,
		Internal:                internalVal,
		Listeners:               listeners,
	}
}
