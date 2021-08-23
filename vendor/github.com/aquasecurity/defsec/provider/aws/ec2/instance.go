package ec2

import (
	"github.com/aquasecurity/defsec/definition"
	"github.com/owenrumney/squealer/pkg/squealer"
)

type Instance struct {
	*definition.Metadata
	MetadataOptions MetadataOptions
	UserData        definition.StringValue
}

type MetadataOptions struct {
	*definition.Metadata
	HttpTokens   definition.StringValue
	HttpEndpoint definition.StringValue
}

func (i *Instance) RequiresIMDSToken() bool {
	return i.MetadataOptions.HttpTokens.EqualTo("required")
}

func (i *Instance) HasHTTPEndpointDisabled() bool {
	return i.MetadataOptions.HttpEndpoint.EqualTo("disabled")
}

func (i *Instance) HasSensitiveInformationInUserData() bool {
	scanner := squealer.NewStringScanner()
	return scanner.Scan(i.UserData.Value).TransgressionFound
}
