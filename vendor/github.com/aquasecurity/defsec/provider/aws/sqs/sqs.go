package sqs

import (
	"github.com/aquasecurity/trivy-config-parsers/types"
)

type SQS struct {
	types.Metadata
	Queues []Queue
}

type Queue struct {
	types.Metadata
	Encryption Encryption
	Policies   []types.StringValue
}

type Encryption struct {
	types.Metadata
	KMSKeyID types.StringValue
}
