package elb

import (
	"github.com/aquasecurity/defsec/provider/aws/elb"
	"github.com/aquasecurity/trivy-config-parsers/terraform"
	"github.com/aquasecurity/trivy-config-parsers/types"
)

func Adapt(modules terraform.Modules) elb.ELB {

	adapter := adapter{
		listenerIDs: modules.GetChildResourceIDMapByType("aws_lb_listener", "aws_alb_listener"),
	}

	return elb.ELB{
		LoadBalancers: adapter.adaptLoadBalancers(modules),
	}
}

type adapter struct {
	listenerIDs terraform.ResourceIDResolutions
}

func (a *adapter) adaptLoadBalancers(modules terraform.Modules) []elb.LoadBalancer {
	var loadBalancers []elb.LoadBalancer
	for _, resource := range modules.GetResourcesByType("aws_lb") {
		loadBalancers = append(loadBalancers, a.adaptLoadBalancer(resource, modules))
	}
	for _, resource := range modules.GetResourcesByType("aws_alb") {
		loadBalancers = append(loadBalancers, a.adaptLoadBalancer(resource, modules))
	}
	for _, resource := range modules.GetResourcesByType("aws_elb") {
		loadBalancers = append(loadBalancers, a.adaptLoadBalancer(resource, modules))
	}

	orphanResources := modules.GetResourceByIDs(a.listenerIDs.Orphans()...)
	if len(orphanResources) > 0 {
		orphanage := elb.LoadBalancer{
			Metadata: types.NewUnmanagedMetadata(),
			Type:     types.StringDefault(elb.TypeApplication, types.NewUnmanagedMetadata()),
		}
		for _, listenerResource := range orphanResources {
			orphanage.Listeners = append(orphanage.Listeners, adaptListener(listenerResource, "application"))
		}
		loadBalancers = append(loadBalancers, orphanage)
	}

	return loadBalancers
}

func (a *adapter) adaptLoadBalancer(resource *terraform.Block, module terraform.Modules) elb.LoadBalancer {
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
		a.listenerIDs.Resolve(listenerBlock.ID())
		listeners = append(listeners, adaptListener(listenerBlock, typeVal.Value()))
	}
	return elb.LoadBalancer{
		Metadata:                resource.GetMetadata(),
		Type:                    typeVal,
		DropInvalidHeaderFields: dropInvalidHeadersVal,
		Internal:                internalVal,
		Listeners:               listeners,
	}
}

func adaptListener(listenerBlock *terraform.Block, typeVal string) elb.Listener {
	listener := elb.Listener{
		Metadata:  listenerBlock.GetMetadata(),
		Protocol:  types.StringDefault("", listenerBlock.GetMetadata()),
		TLSPolicy: types.StringDefault("", listenerBlock.GetMetadata()),
		DefaultAction: elb.Action{
			Metadata: listenerBlock.GetMetadata(),
			Type:     types.StringDefault("", listenerBlock.GetMetadata()),
		},
	}

	protocolAttr := listenerBlock.GetAttribute("protocol")
	if typeVal == "application" {
		listener.Protocol = protocolAttr.AsStringValueOrDefault("HTTP", listenerBlock)
	}

	sslPolicyAttr := listenerBlock.GetAttribute("ssl_policy")
	listener.TLSPolicy = sslPolicyAttr.AsStringValueOrDefault("", listenerBlock)

	if defaultActionBlock := listenerBlock.GetBlock("default_action"); defaultActionBlock.IsNotNil() {
		listener.DefaultAction.Metadata = defaultActionBlock.GetMetadata()
		actionTypeAttr := defaultActionBlock.GetAttribute("type")
		listener.DefaultAction.Type = actionTypeAttr.AsStringValueOrDefault("", defaultActionBlock)
	}

	return listener
}
