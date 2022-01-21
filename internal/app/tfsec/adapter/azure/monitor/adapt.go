package monitor

import (
	"github.com/aquasecurity/defsec/provider/azure/monitor"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules block.Modules) monitor.Monitor {
	return monitor.Monitor{
		LogProfiles: adaptLogProfiles(modules),
	}
}

func adaptLogProfiles(modules block.Modules) []monitor.LogProfile {
	var logProfiles []monitor.LogProfile

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_monitor_log_profile") {
			logProfiles = append(logProfiles, adaptLogProfile(resource))
		}
	}
	return logProfiles
}

func adaptLogProfile(resource *block.Block) monitor.LogProfile {
	retentionPolicyBlock := resource.GetBlock("retention_policy")

	enabledAttr := retentionPolicyBlock.GetAttribute("enabled")
	enabledVal := enabledAttr.AsBoolValueOrDefault(false, resource)

	daysAttr := retentionPolicyBlock.GetAttribute("days")
	daysVal := daysAttr.AsIntValueOrDefault(0, resource)

	categoriesAttr := resource.GetAttribute("categories")
	var categoriesVal []types.StringValue
	categories := categoriesAttr.ValueAsStrings()
	for _, category := range categories {
		categoriesVal = append(categoriesVal, types.String(category, *resource.GetMetadata()))
	}

	locationsAttr := resource.GetAttribute("locations")
	var locationsVal []types.StringValue
	locations := locationsAttr.ValueAsStrings()
	for _, location := range locations {
		locationsVal = append(locationsVal, types.String(location, *resource.GetMetadata()))
	}

	return monitor.LogProfile{
		Metadata: *resource.GetMetadata(),
		RetentionPolicy: monitor.RetentionPolicy{
			Enabled: enabledVal,
			Days:    daysVal,
		},
		Categories: categoriesVal,
		Locations:  locationsVal,
	}
}
