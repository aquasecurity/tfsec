package config

import "github.com/aquasecurity/defsec/types"

type Config struct {
	ConfigurationAggregrator ConfigurationAggregrator
}

type ConfigurationAggregrator struct {
	SourceAllRegions types.BoolValue
	IsDefined        bool
}
