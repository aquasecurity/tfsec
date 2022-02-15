package config

import "github.com/aquasecurity/trivy-config-parsers/types"

type Config struct {
	types.Metadata
	ConfigurationAggregrator ConfigurationAggregrator
}

type ConfigurationAggregrator struct {
	types.Metadata
	SourceAllRegions types.BoolValue
	IsDefined        bool
}
