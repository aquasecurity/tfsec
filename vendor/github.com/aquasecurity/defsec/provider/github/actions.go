package github

import "github.com/aquasecurity/defsec/types"

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

func (a *EnvironmentSecret) GetMetadata() *types.Metadata {
	return &a.Metadata
}

func (a *EnvironmentSecret) GetRawValue() interface{} {
	return nil
}
