package apigateway

import "github.com/aquasecurity/defsec/types"

type APIGateway struct {
	types.Metadata
	APIs        []API
	DomainNames []DomainName
}

const (
	ProtocolTypeUnknown   string = ""
	ProtocolTypeREST      string = "REST"
	ProtocolTypeHTTP      string = "HTTP"
	ProtocolTypeWebsocket string = "WEBSOCKET"
)

type API struct {
	types.Metadata
	Name         types.StringValue
	Version      types.IntValue
	ProtocolType types.StringValue
	Stages       []Stage
	RESTMethods  []RESTMethod
}

type Stage struct {
	types.Metadata
	Name               types.StringValue
	Version            types.IntValue
	AccessLogging      AccessLogging
	RESTMethodSettings RESTMethodSettings
	XRayTracingEnabled types.BoolValue
}

type AccessLogging struct {
	types.Metadata
	CloudwatchLogGroupARN types.StringValue
}

type RESTMethodSettings struct {
	types.Metadata
	CacheDataEncrypted types.BoolValue
}

const (
	AuthorizationNone             = "NONE"
	AuthorizationCustom           = "CUSTOM"
	AuthorizationIAM              = "AWS_IAM"
	AuthorizationCognitoUserPools = "COGNITO_USER_POOLS"
)

type RESTMethod struct {
	types.Metadata
	HTTPMethod        types.StringValue
	AuthorizationType types.StringValue
	APIKeyRequired    types.BoolValue
}

type DomainName struct {
	types.Metadata
	Name           types.StringValue
	Version        types.IntValue
	SecurityPolicy types.StringValue
}

func (a *API) GetMetadata() *types.Metadata {
	return &a.Metadata
}

func (a *API) GetRawValue() interface{} {
	return nil
}

func (s *Stage) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s *Stage) GetRawValue() interface{} {
	return nil
}

func (m *RESTMethod) GetMetadata() *types.Metadata {
	return &m.Metadata
}

func (m *RESTMethod) GetRawValue() interface{} {
	return nil
}

func (d *DomainName) GetMetadata() *types.Metadata {
	return &d.Metadata
}

func (d *DomainName) GetRawValue() interface{} {
	return nil
}

func (a *APIGateway) GetMetadata() *types.Metadata {
	return &a.Metadata
}

func (a *APIGateway) GetRawValue() interface{} {
	return nil
}

func (a *AccessLogging) GetMetadata() *types.Metadata {
	return &a.Metadata
}

func (a *AccessLogging) GetRawValue() interface{} {
	return nil
}

func (r *RESTMethodSettings) GetMetadata() *types.Metadata {
	return &r.Metadata
}

func (r *RESTMethodSettings) GetRawValue() interface{} {
	return nil
}
