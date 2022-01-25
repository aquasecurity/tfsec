package config

import "github.com/aquasecurity/defsec/types"

type Config struct {
	types.Metadata
	ConfigurationAggregrator ConfigurationAggregrator
}

type ConfigurationAggregrator struct {
	types.Metadata
	SourceAllRegions types.BoolValue
	IsDefined        bool
}


func (c *Config) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Config) GetRawValue() interface{} {
	return nil
}    


func (c *ConfigurationAggregrator) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *ConfigurationAggregrator) GetRawValue() interface{} {
	return nil
}    
