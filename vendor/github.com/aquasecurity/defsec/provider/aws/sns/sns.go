package sns

import "github.com/aquasecurity/trivy-config-parsers/types"

type SNS struct {
	types.Metadata
	Topics []Topic
}

type Topic struct {
	types.Metadata
	Encryption Encryption
}

type Encryption struct {
	types.Metadata
	KMSKeyID types.StringValue
}
