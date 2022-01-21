package datafactory

import (
	"github.com/aquasecurity/defsec/provider/azure/datafactory"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules block.Modules) datafactory.DataFactory {
	return datafactory.DataFactory{
		DataFactories: adaptFactories(modules),
	}
}

func adaptFactories(modules block.Modules) []datafactory.Factory {
	var factories []datafactory.Factory

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_data_factory") {
			factories = append(factories, adaptFactory(resource))
		}
	}
	return factories
}

func adaptFactory(resource *block.Block) datafactory.Factory {
	enablePublicNetworkAttr := resource.GetAttribute("public_network_enabled")
	enablePublicNetworkVal := enablePublicNetworkAttr.AsBoolValueOrDefault(true, resource)

	return datafactory.Factory{
		EnablePublicNetwork: enablePublicNetworkVal,
	}
}
