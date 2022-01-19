package sam

import "github.com/aquasecurity/defsec/types"

type API struct {
	types.Metadata
	Name                types.StringValue
	TracingEnabled      types.BoolValue
	DomainConfiguration DomainConfiguration
	AccessLogging       AccessLogging
	RESTMethodSettings  RESTMethodSettings
}

type ApiAuth struct {
	types.Metadata
	ApiKeyRequired types.BoolValue
}

type AccessLogging struct {
	types.Metadata
	CloudwatchLogGroupARN types.StringValue
}

type DomainConfiguration struct {
	types.Metadata
	Name           types.StringValue
	SecurityPolicy types.StringValue
}

type RESTMethodSettings struct {
	types.Metadata
	CacheDataEncrypted types.BoolValue
	LoggingEnabled     types.BoolValue
	DataTraceEnabled   types.BoolValue
	MetricsEnabled     types.BoolValue
}

func (a *API) GetMetadata() *types.Metadata {
	return &a.Metadata
}

func (a *API) GetRawValue() interface{} {
	return nil
}

func (a *AccessLogging) GetMetadata() *types.Metadata {
	return &a.Metadata
}

func (a *AccessLogging) GetRawValue() interface{} {
	return nil
}

func (a *DomainConfiguration) GetMetadata() *types.Metadata {
	return &a.Metadata
}

func (a *DomainConfiguration) GetRawValue() interface{} {
	return nil
}

func (a *RESTMethodSettings) GetMetadata() *types.Metadata {
	return &a.Metadata
}

func (a *RESTMethodSettings) GetRawValue() interface{} {
	return nil
}


func (a *ApiAuth) GetMetadata() *types.Metadata {
	return &a.Metadata
}

func (a *ApiAuth) GetRawValue() interface{} {
	return nil
}    
