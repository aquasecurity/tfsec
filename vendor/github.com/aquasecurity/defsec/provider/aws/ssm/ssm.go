package ssm

import "github.com/aquasecurity/defsec/types"

type SSM struct {
	Secrets []Secret
}

type Secret struct {
	types.Metadata
	KMSKeyID types.StringValue
}

func (v *Secret) GetMetadata() *types.Metadata {
	return &v.Metadata
}

func (v *Secret) GetRawValue() interface{} {
	return nil
}
