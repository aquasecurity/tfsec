package github

import "github.com/aquasecurity/trivy-config-parsers/types"

type Action struct {
	types.Metadata
	EnvironmentSecrets []EnvironmentSecret
}

type EnvironmentSecret struct {
	types.Metadata
	Repository     types.StringValue
	Environment    types.StringValue
	SecretName     types.StringValue
	PlainTextValue types.StringValue
	EncryptedValue types.StringValue
}
