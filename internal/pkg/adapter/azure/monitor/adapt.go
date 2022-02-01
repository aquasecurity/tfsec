package monitor

import (
	"github.com/aquasecurity/defsec/provider/azure/monitor"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
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

	logProfile := monitor.LogProfile{
		Metadata: resource.Metadata(),
		RetentionPolicy: monitor.RetentionPolicy{
			Metadata: resource.Metadata(),
			Enabled:  types.BoolDefault(false, resource.Metadata()),
			Days:     types.IntDefault(0, resource.Metadata()),
		},
	}

	if retentionPolicyBlock := resource.GetBlock("retention_policy"); retentionPolicyBlock.IsNotNil() {
		logProfile.RetentionPolicy.Metadata = retentionPolicyBlock.Metadata()
		enabledAttr := retentionPolicyBlock.GetAttribute("enabled")
		logProfile.RetentionPolicy.Enabled = enabledAttr.AsBoolValueOrDefault(false, resource)
		daysAttr := retentionPolicyBlock.GetAttribute("days")
		logProfile.RetentionPolicy.Days = daysAttr.AsIntValueOrDefault(0, resource)
	}

	if categoriesAttr := resource.GetAttribute("categories"); categoriesAttr.IsNotNil() {
		for _, category := range categoriesAttr.ValueAsStrings() {
			logProfile.Categories = append(logProfile.Categories, types.String(category, resource.Metadata()))
		}
	}

	if locationsAttr := resource.GetAttribute("locations"); locationsAttr.IsNotNil() {
		for _, location := range locationsAttr.ValueAsStrings() {
			logProfile.Locations = append(logProfile.Locations, types.String(location, resource.Metadata()))
		}
	}

	return logProfile
}
