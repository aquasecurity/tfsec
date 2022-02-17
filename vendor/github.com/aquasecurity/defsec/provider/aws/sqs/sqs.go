package sqs

import (
	"github.com/aquasecurity/defsec/provider/aws/iam"
	"github.com/aquasecurity/trivy-config-parsers/types"
)

type SQS struct {
	types.Metadata
	Queues []Queue
}

type Queue struct {
	types.Metadata
	Encryption Encryption
	Policies   []iam.Policy
}

type Encryption struct {
	types.Metadata
	KMSKeyID types.StringValue
}
