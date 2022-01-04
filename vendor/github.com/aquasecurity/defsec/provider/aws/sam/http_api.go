package sam

import "github.com/aquasecurity/defsec/types"

type HttpAPI struct {
	types.Metadata
	Name                 types.StringValue
	AccessLogging        AccessLogging
	DefaultRouteSettings RouteSettings
	DomainConfiguration  DomainConfiguration
}

type RouteSettings struct {
	types.Metadata
	LoggingEnabled         types.BoolValue
	DataTraceEnabled       types.BoolValue
	DetailedMetricsEnabled types.BoolValue
}

func (a *HttpAPI) GetMetadata() *types.Metadata {
	return &a.Metadata
}

func (a *HttpAPI) GetRawValue() interface{} {
	return nil
}

func (a *RouteSettings) GetMetadata() *types.Metadata {
	return &a.Metadata
}

func (a *RouteSettings) GetRawValue() interface{} {
	return nil
}
