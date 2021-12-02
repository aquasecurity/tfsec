package apigateway

import "github.com/aquasecurity/defsec/types"

type APIGateway struct {
	APIs        []API
	DomainNames []DomainName
}

const (
	ProtoclTypeUnknown    string = ""
	ProtocolTypeREST      string = "REST"
	ProtocolTypeHTTP      string = "HTTP"
	ProtocolTypeWebsocket string = "WEBSOCKET"
)

type API struct {
	types.Metadata
	Name         types.StringValue
	ProtocolType types.StringValue
	Stages       []Stage
	RESTMethods  []RESTMethod
}

type Stage struct {
	types.Metadata
	Name               types.StringValue
	AccessLogging      AccessLogging
	RESTMethodSettings RESTMethodSettings
	XRayTracingEnabled types.BoolValue
}

type AccessLogging struct {
	types.Metadata
	CloudwatchLogGroupARN types.StringValue
}

type RESTMethodSettings struct {
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
