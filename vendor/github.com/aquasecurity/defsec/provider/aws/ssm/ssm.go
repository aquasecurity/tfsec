package ssm

import "github.com/aquasecurity/trivy-config-parsers/types"

type SSM struct {
	types.Metadata
	Secrets []Secret
}

type Secret struct {
	types.Metadata
	KMSKeyID types.StringValue
}

const DefaultKMSKeyID = "alias/aws/secretsmanager"
