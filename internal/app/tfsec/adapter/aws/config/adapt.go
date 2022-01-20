package config

import (
	"github.com/aquasecurity/defsec/provider/aws/config"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules block.Modules) config.Config {
	return config.Config{
		ConfigurationAggregrator: adaptConfigurationAggregrator(modules),
	}
}

func adaptConfigurationAggregrator(modules block.Modules) config.ConfigurationAggregrator {
	var configurationAggregrator config.ConfigurationAggregrator

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_config_configuration_aggregator") {
			configurationAggregrator.IsDefined = true

			aggregationBlock := resource.GetFirstMatchingBlock("account_aggregation_source", "organization_aggregation_source")
			if aggregationBlock.IsNil() {
				configurationAggregrator.SourceAllRegions = types.Bool(false, *resource.GetMetadata())
			} else {
				allRegionsAttr := aggregationBlock.GetAttribute("all_regions")
				allRegionsVal := allRegionsAttr.AsBoolValueOrDefault(false, aggregationBlock)
				configurationAggregrator.SourceAllRegions = allRegionsVal
			}
		}
	}
	return configurationAggregrator
}
